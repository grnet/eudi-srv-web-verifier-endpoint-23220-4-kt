/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.verifier.endpoint.port.input

import arrow.core.Either
import arrow.core.raise.Raise
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import eu.europa.ec.eudi.prex.PresentationSubmission
import eu.europa.ec.eudi.verifier.endpoint.domain.*
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.RequestObjectRetrieved
import eu.europa.ec.eudi.verifier.endpoint.domain.Presentation.Submitted
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.CreateQueryWalletResponseRedirectUri
import eu.europa.ec.eudi.verifier.endpoint.port.out.cfg.GenerateResponseCode
import eu.europa.ec.eudi.verifier.endpoint.port.out.jose.VerifyJarmJwtSignature
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.LoadPresentationByRequestId
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.PublishPresentationEvent
import eu.europa.ec.eudi.verifier.endpoint.port.out.persistence.StorePresentation
import eu.europa.ec.eudi.verifier.endpoint.port.input.ValidToken
import id.walt.mdoc.dataretrieval.DeviceResponse
import id.walt.mdoc.doc.MDoc
import id.walt.mdoc.mso.MSO
import id.walt.mdoc.mso.StatusElement
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.PublicKey
import java.text.ParseException
import java.time.Clock
import java.util.Base64
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import kotlinx.serialization.json.Json



/**
 * Represent the Authorisation Response placed by wallet
 */
data class AuthorisationResponseTO(
    val state: String?, // this is the request_id
    val error: String? = null,
    val errorDescription: String? = null,
    val idToken: String? = null,
    val vpToken: String? = null,
    val presentationSubmission: PresentationSubmission? = null,
)

sealed interface AuthorisationResponse {

    data class DirectPost(val response: AuthorisationResponseTO) : AuthorisationResponse
    data class DirectPostJwt(val state: String?, val jarm: Jwt) : AuthorisationResponse
}

sealed interface WalletResponseValidationError {
    data object MissingState : WalletResponseValidationError
    data object PresentationNotFound : WalletResponseValidationError

    data class UnexpectedResponseMode(
        val requestId: RequestId,
        val expected: ResponseModeOption,
        val actual: ResponseModeOption,
    ) : WalletResponseValidationError

    data object RevokedVpToken : WalletResponseValidationError

    data object PresentationNotInExpectedState : WalletResponseValidationError

    data object IncorrectStateInJarm : WalletResponseValidationError
    data object MissingIdToken : WalletResponseValidationError
    data object MissingVpTokenOrPresentationSubmission : WalletResponseValidationError
}

context(Raise<WalletResponseValidationError>)
internal fun AuthorisationResponseTO.toDomain(presentation: RequestObjectRetrieved): WalletResponse {
    fun requiredIdToken(): WalletResponse.IdToken {
        ensureNotNull(idToken) { WalletResponseValidationError.MissingIdToken }
        return WalletResponse.IdToken(idToken)
    }

    fun requiredVpToken(): WalletResponse.VpToken {
        ensureNotNull(vpToken) { WalletResponseValidationError.MissingVpTokenOrPresentationSubmission }
        ensureNotNull(presentationSubmission) { WalletResponseValidationError.MissingVpTokenOrPresentationSubmission }
        return WalletResponse.VpToken(vpToken, presentationSubmission)
    }

    fun requiredIdAndVpToken(): WalletResponse.IdAndVpToken {
        val a = requiredIdToken()
        val b = requiredVpToken()
        return WalletResponse.IdAndVpToken(a.idToken, b.vpToken, b.presentationSubmission)
    }

    val maybeError: WalletResponse.Error? = error?.let { WalletResponse.Error(it, errorDescription) }

    return maybeError ?: when (presentation.type) {
        is PresentationType.IdTokenRequest -> WalletResponse.IdToken(requiredIdToken().idToken)
        is PresentationType.VpTokenRequest -> WalletResponse.VpToken(
            requiredVpToken().vpToken,
            requiredVpToken().presentationSubmission,
        )

        is PresentationType.IdAndVpToken -> WalletResponse.IdAndVpToken(
            requiredIdAndVpToken().idToken,
            requiredIdAndVpToken().vpToken,
            requiredIdAndVpToken().presentationSubmission,
        )
    }
}

@Serializable
data class WalletResponseAcceptedTO(
    @SerialName("redirect_uri") val redirectUri: String,
)

@Serializable
data class RevocationCheckTO(
    @SerialName("uri") val uri: String = "",
    @SerialName("index") val index: Int = 0,
)

@Serializable
data class StatusListAgg(
    @SerialName("iss") val iss: String = "",
    @SerialName("sub") val sub: String = "",
    @SerialName("exp") val exp: Int = 0,
    @SerialName("iat") val iat: Int = 0,
    @SerialName("status_list") val status_list: StatusList  = StatusList(),
)

@Serializable
data class StatusList(
    @SerialName("bits") val bits: Int = 0,
    @SerialName("lst") val lst: String = "",
    @SerialName("aggregation_uri") val aggregation_uri: String = "",
)

enum class ValidToken(val value: Int) {
    VALID(0),
    INVALID(1)
}

/**
 * This is use case 12 of the [Presentation] process.
 *
 * The caller (wallet) may POST the [AuthorisationResponseTO] to the verifier back-end
 */
fun interface PostWalletResponse {

    context(Raise<WalletResponseValidationError>)
    suspend operator fun invoke(walletResponse: AuthorisationResponse): WalletResponseAcceptedTO?
}

class PostWalletResponseLive(
    private val loadPresentationByRequestId: LoadPresentationByRequestId,
    private val storePresentation: StorePresentation,
    private val verifyJarmJwtSignature: VerifyJarmJwtSignature,
    private val clock: Clock,
    private val verifierConfig: VerifierConfig,
    private val generateResponseCode: GenerateResponseCode,
    private val createQueryWalletResponseRedirectUri: CreateQueryWalletResponseRedirectUri,
    private val publishPresentationEvent: PublishPresentationEvent,
    private val logger: Logger = LoggerFactory.getLogger(PostWalletResponseLive::class.java)
) : PostWalletResponse {

    context(Raise<WalletResponseValidationError>)
    override suspend operator fun invoke(
        walletResponse: AuthorisationResponse,
    ): WalletResponseAcceptedTO? = coroutineScope {
        val presentation = loadPresentation(walletResponse)

        doInvoke(presentation, walletResponse).fold(
            ifLeft = { cause ->
                logFailure(presentation, cause)
                raise(cause)
            },
            ifRight = { (submitted, accepted) ->
                logWalletResponsePosted(submitted, accepted)
                accepted
            },
        )
    }

    private suspend fun doInvoke(
        presentation: Presentation,
        walletResponse: AuthorisationResponse,
    ): Either<WalletResponseValidationError, Pair<Submitted, WalletResponseAcceptedTO?>> =
        either {
            ensure(presentation is RequestObjectRetrieved) {
                WalletResponseValidationError.PresentationNotInExpectedState
            }

            // Verify the AuthorisationResponse matches what is expected for the Presentation
            val responseMode = walletResponse.responseMode()
            ensure(presentation.responseMode == responseMode) {
                WalletResponseValidationError.UnexpectedResponseMode(
                    presentation.requestId,
                    expected = presentation.responseMode,
                    actual = responseMode,
                )
            }

            val responseObject = responseObject(walletResponse, presentation)
            // Verify that the VpToken is not revoked.
            ensure(validateVpToken(responseObject)) {
                WalletResponseValidationError.RevokedVpToken
            }

            val submitted = submit(presentation, responseObject).also { storePresentation(it) }

            val accepted = when (val getWalletResponseMethod = presentation.getWalletResponseMethod) {
                is GetWalletResponseMethod.Redirect ->
                    with(createQueryWalletResponseRedirectUri) {
                        requireNotNull(submitted.responseCode) { "ResponseCode expected in Submitted state but not found" }
                        val redirectUri = getWalletResponseMethod.redirectUri(submitted.responseCode)
                        WalletResponseAcceptedTO(redirectUri.toExternalForm())
                    }

                GetWalletResponseMethod.Poll -> null
            }
            submitted to accepted
        }

    context(Raise<WalletResponseValidationError>)
    private suspend fun loadPresentation(walletResponse: AuthorisationResponse): Presentation {
        val state = when (walletResponse) {
            is AuthorisationResponse.DirectPost -> walletResponse.response.state
            is AuthorisationResponse.DirectPostJwt -> walletResponse.state
        }
        ensureNotNull(state) { WalletResponseValidationError.MissingState }
        val requestId = RequestId(state)

        val presentation = loadPresentationByRequestId(requestId)
        return ensureNotNull(presentation) { WalletResponseValidationError.PresentationNotFound }
    }

    context(Raise<WalletResponseValidationError>)
    private fun responseObject(
        walletResponse: AuthorisationResponse,
        presentation: RequestObjectRetrieved,
    ): AuthorisationResponseTO = when (walletResponse) {
        is AuthorisationResponse.DirectPost -> walletResponse.response
        is AuthorisationResponse.DirectPostJwt -> {
            val response = verifyJarmJwtSignature(
                jarmOption = verifierConfig.clientMetaData.jarmOption,
                ephemeralEcPrivateKey = presentation.ephemeralEcPrivateKey,
                jarmJwt = walletResponse.jarm,
            ).getOrThrow()
            ensure(response.state == walletResponse.state) { WalletResponseValidationError.IncorrectStateInJarm }
            response
        }
    }

    context(Raise<WalletResponseValidationError>)
    private suspend fun submit(
        presentation: RequestObjectRetrieved,
        responseObject: AuthorisationResponseTO,
    ): Submitted {
        // add the wallet response to the presentation
        val walletResponse = responseObject.toDomain(presentation)
        val responseCode = when (presentation.getWalletResponseMethod) {
            GetWalletResponseMethod.Poll -> null
            is GetWalletResponseMethod.Redirect -> generateResponseCode()
        }
        return presentation.submit(clock, walletResponse, responseCode).getOrThrow()
    }

    private suspend fun logWalletResponsePosted(p: Submitted, accepted: WalletResponseAcceptedTO?) {
        val event =
            PresentationEvent.WalletResponsePosted(p.id, p.submittedAt, p.walletResponse.toTO(), accepted)
        publishPresentationEvent(event)
    }

    private suspend fun logFailure(p: Presentation, cause: WalletResponseValidationError) {
        val event = PresentationEvent.WalletFailedToPostResponse(p.id, clock.instant(), cause)
        publishPresentationEvent(event)
    }

    private suspend fun validateVpToken(walletResponse: AuthorisationResponseTO): Boolean {
        val vpToken = walletResponse.vpToken
        logger.debug("Vptoken is: ${vpToken}")
        try {
            val cborBytes: ByteArray = Base64.getUrlDecoder().decode(vpToken)
            logger.debug("Decoded bytes of VpToken: ${cborBytes.decodeToString()} of size ${cborBytes.size}")
            val deviceResponse: DeviceResponse = DeviceResponse.Companion.fromCBORHex(cborBytes.decodeToString())
            logger.debug("Processed DeviceResponse: ${deviceResponse}")

            val mdoc: MDoc = deviceResponse.documents.stream().filter{ it.verifyDocType() }.findFirst().get()
            val mso: MSO? = mdoc.MSO
            if (mso == null) {
                logger.warn("No MSO available, failure in verification")
                return false
            }

            val statusEl: StatusElement? = mso.statusElement
            if (statusEl == null) {
                logger.warn("MSO does not contain status element, skipping validation")
                return true
            }
            val uri: String = statusEl.statusListInfo.uri.value
            val idx: Int = statusEl.statusListInfo.idx.value.toInt()
            logger.debug("Read status list uri: ${uri}, index: ${idx}")

            return vpTokenIsValid(uri, idx)
        } catch (e: Exception) {
            logger.warn("ATTENTION: Revocation check for vp_token failed with exception ${e}. Check input and bypass for now.")
            return true
        }
    }

    private suspend fun vpTokenIsValid(uri: String, idx: Int): Boolean {
        logger.info("Handling RevocationCheck uri=${uri}, index = ${idx}")
        val client = HttpClient(CIO)
        val response: HttpResponse = client.get(uri)
        val body: String = response.body()
        logger.debug("Status list returned: ${body}")
        client.close()

        // Get and validate JWK
        val jwkJsonString: String = GetWalletResponseLive::class.java.getResource("/lsp-public-key.jwk.json").readText()
        logger.debug("JWK string retrieved: ${jwkJsonString}")
        val jwk: JWK? = parseJWKString(jwkJsonString)
        logger.debug("JWK parsed: ${jwk}")
        val verified: Boolean = verifyJwt(jwk!!, body)
        logger.debug("Status list verified? ${verified}")

        // Decode JWT
        val header_payload = decodeToken(body)
        val header_payload_json = Json.decodeFromString<StatusListAgg>(header_payload)
        logger.debug("Decoded status list: ${header_payload_json}")

        // Extract and check status bit
        val lst = header_payload_json.status_list.lst
        logger.debug("lst: ${lst}")
        val byte: Int = idx / 8
        val bit: Int = idx % 8
        logger.debug("byte: ${byte}, bit: ${bit}")
        var bit_status: Int = 0
        if (byte < body.toByteArray().size) {
            bit_status = (body.toByteArray()[byte].toInt() shr bit) and 1
            logger.info("Bit value is: ${bit_status} (0=VALID vpToken, 1=REVOKED vpToken)")
        }
        return bit_status == ValidToken.VALID.value
    }

    private fun decodeToken(jwt: String): String {
        val parts = jwt.split(".")
        return try {
            val charset = charset("UTF-8")
            val header = String(Base64.getUrlDecoder().decode(parts[0].toByteArray(charset)), charset)
            val payload = String(Base64.getUrlDecoder().decode(parts[1].toByteArray(charset)), charset)
            "$header"
            "$payload"
        } catch (e: Exception) {
            "Error parsing JWT: $e"
        }
    }

    private fun parseJWKString(jsonJwk: String): JWK? {
        return try {
            JWK.parse(jsonJwk)
        } catch (e: ParseException) {
            logger.warn("Could not parse JWK JSON string {}", jsonJwk)
            null
        }
    }

    private fun verifyJwt(jwk: JWK, jwtString: String): Boolean {
        return try {
            when (val publicKey = parseJWK(jwk)) {
                is PublicKey -> {
                    val signedJWT = SignedJWT.parse(jwtString)
                    val verifier: JWSVerifier = createVerifier(publicKey)
                    signedJWT.verify(verifier)
                }

                else -> error("JWK needs to be PublicKey")
            }
        } catch (e: Exception) {
            error(e.message ?: "Unable to verify JWT")
        }
    }

    private fun parseJWK(jwk: JWK): PublicKey? {
        return try {
            if (jwk is ECKey) {
                jwk.toECPublicKey()
            } else if (jwk is RSAKey) {
                jwk.toRSAPublicKey()
            } else {
                null
            }
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    private inline fun <reified T : PublicKey> createVerifier(publicKey: T): JWSVerifier {
        val jwsVerifierFactory = DefaultJWSVerifierFactory().apply {
            // Set the security provider, for example, BouncyCastle
            jcaContext.provider = BouncyCastleProviderSingleton.getInstance()
        }

        return when (publicKey) {
            is RSAPublicKey -> jwsVerifierFactory.createJWSVerifier(
                 JWSHeader.Builder(JWSAlgorithm.RS256).build(), publicKey
            )

            is ECPublicKey -> jwsVerifierFactory.createJWSVerifier(
                JWSHeader.Builder(JWSAlgorithm.ES256).build(), publicKey
            )

            else -> throw IllegalArgumentException("Unsupported key type")
        }
    }

}

/**
 * Gets the [ResponseModeOption] that corresponds to the receiver [AuthorisationResponse].
 */
private fun AuthorisationResponse.responseMode(): ResponseModeOption = when (this) {
    is AuthorisationResponse.DirectPost -> ResponseModeOption.DirectPost
    is AuthorisationResponse.DirectPostJwt -> ResponseModeOption.DirectPostJwt
}