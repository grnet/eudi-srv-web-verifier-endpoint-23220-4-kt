package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import cbor.Cbor
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.EncodedCBORElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.toJsonElement
import id.walt.mdoc.dataretrieval.DeviceResponse
import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.IOException
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

internal class EbsiApi

private val logger: Logger = LoggerFactory.getLogger(EbsiApi::class.java)

const val EBSI_AGENT_ADDRESS = "https://snf-36159.ok-kno.grnetcloud.net/ebsi-agent"

@Serializable
private data class VerifyToken(
    val token: String
)

@JvmSynthetic
internal suspend fun verifyVcToken(vcToken: String): String {
    val client = HttpClient {
        install(ContentNegotiation) {
            json(Json {
                ignoreUnknownKeys = true
            })
        }
    }

    val url = "$EBSI_AGENT_ADDRESS/verify-vc"

    val response: HttpResponse = client.post(url) {
        contentType(ContentType.Application.Json)
        setBody(VerifyToken(vcToken))
    }

    if (!response.status.isSuccess()) {
        throw IOException("EUDI Wallet EBSI! Unexpected code ${response.status}, body: ${response.bodyAsText()}")
    }

    return response.bodyAsText()
}

@OptIn(ExperimentalEncodingApi::class, ExperimentalSerializationApi::class)
fun getNamespaceFromVpToken(vpToken: String): List<EncodedCBORElement>? {
    val base64Dec = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)
    val cbor =  base64Dec.decode(vpToken)
    logger.info("cbor=${cbor}")
    val cborParsed = Cbor.decodeFromByteArray<DeviceResponse>(cbor)
    logger.info("cborParsed=${cborParsed}")
    return cborParsed.documents[0].issuerSigned.nameSpaces?.get("eu.europa.ec.eudi.pid.1")
}

suspend fun processPresentationCredential(vpToken: String) {
    val namespace = getNamespaceFromVpToken(vpToken)
    namespace?.forEach { element ->
        val decodedElement = element.decodeDataElement<DataElement>()
        logger.info("decodedElement=${decodedElement}")
        (decodedElement as? MapElement)?.run {
            val entry = toJsonElement().jsonObject
            val elementId = entry["elementIdentifier"]
            logger.info("Processing element ID: ${elementId.toString()}")
            when (elementId) {
                is JsonPrimitive -> {
                    val key = elementId.content
                    when (val elementValue = entry["elementValue"]) {
                        is JsonPrimitive -> {
                            if (key == "vc_token") {
                                val result = verifyVcToken(elementValue.content)
                                logger.info("verificationResult=${result}")
                            }
                        }
                        else -> logger.info("Ignoring value: ${elementValue.toString()}")
                    }
                }
                else -> logger.info("Error: bad ID")
            }
        }
    }

}