package eu.europa.ec.eudi.verifier.endpoint.port.input.jose

import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import eu.europa.ec.eudi.verifier.endpoint.port.input.AuthorisationResponseTO
import eu.europa.ec.eudi.verifier.endpoint.port.input.GetWalletResponseLive
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
import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerialName
import kotlinx.serialization.json.Json
import org.slf4j.Logger
import org.slf4j.LoggerFactory


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



fun interface ValidateToken {
    suspend operator fun invoke(token: String?): Boolean
}

class ValidateVpToken(): ValidateToken {
    private val logger: Logger = LoggerFactory.getLogger(ValidateVpToken::class.java)

    override suspend fun invoke(vpToken: String?): Boolean {
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