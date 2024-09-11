package eu.europa.ec.eudi.verifier.endpoint.adapter.input.web

import COSE.AlgorithmID
import eu.europa.ec.eudi.verifier.endpoint.VerifierApplicationTest
import java.io.File
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import id.walt.mdoc.COSECryptoProviderKeyInfo
import id.walt.mdoc.dataelement.DataElement
import id.walt.mdoc.dataelement.toDataElement
import id.walt.mdoc.dataelement.FullDateElement
import id.walt.mdoc.dataelement.MapElement
import id.walt.mdoc.dataelement.MapKey
import id.walt.mdoc.dataelement.StringElement
import id.walt.mdoc.dataretrieval.DeviceResponse
import id.walt.mdoc.doc.MDocBuilder
import id.walt.mdoc.mso.DeviceKeyInfo
import id.walt.mdoc.mso.MSO
import id.walt.mdoc.mso.StatusElement
import id.walt.mdoc.mso.StatusListInfo
import id.walt.mdoc.mso.ValidityInfo
import id.walt.mdoc.SimpleCOSECryptoProvider
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.LocalDate
import kotlinx.serialization.*
import kotlinx.serialization.cbor.*
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.slf4j.Logger
import org.slf4j.LoggerFactory

@Serializable
data class Project(val name: String, val language: String)

fun ByteArray.toAsciiHexString() = joinToString("") {
    if (it in 32..127) it.toInt().toChar().toString() else
        "{${it.toUByte().toString(16).padStart(2, '0').uppercase()}}"
}

@VerifierApplicationTest
internal class MDocCBORTest {
    private val logger: Logger = LoggerFactory.getLogger(MDocCBORTest::class.java)

    @Test
    @OptIn(ExperimentalSerializationApi::class)
    fun cborSimpleTest() {
        val data = Project("Marios", "Python")
        val bytes: ByteArray = Cbor.encodeToByteArray(data)
        logger.info("Project encoded in Kotlin: ${bytes.toAsciiHexString()}")
        val objK = Cbor.decodeFromByteArray<Project>(bytes)
        logger.info("Project decoded in Kotlin: ${objK}")

        val bytesCBOR: ByteArray = MDocCBORTest::class.java.getResource("/project.cbor").readBytes()
        val objP = Cbor.decodeFromByteArray<Project>(bytesCBOR)
        logger.info("Python project decoded in Kotlin: ${objP}")
        assertTrue(objK == objP)
    }

    @Test
    @OptIn(ExperimentalSerializationApi::class)
    fun mdocCBORTest() {
        // Example taken from walt.id: https://github.com/walt-id/waltid-mdoc/tree/main?tab=readme-ov-file#present-mdl-document-with-selective-disclosure-for-a-given-mdoc-request
        // try deserializing example from ISO/IEC FDIS 18013-5: D.4.1.2 mdoc response
        val serializedDoc: String = "a36776657273696f6e63312e3069646f63756d656e747381a367646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c6973737565725369676e6564a26a6e616d65537061636573a1716f72672e69736f2e31383031332e352e3186d8185863a4686469676573744944006672616e646f6d58208798645b20ea200e19ffabac92624bee6aec63aceedecfb1b80077d22bfc20e971656c656d656e744964656e7469666965726b66616d696c795f6e616d656c656c656d656e7456616c756563446f65d818586ca4686469676573744944036672616e646f6d5820b23f627e8999c706df0c0a4ed98ad74af988af619b4bb078b89058553f44615d71656c656d656e744964656e7469666965726a69737375655f646174656c656c656d656e7456616c7565d903ec6a323031392d31302d3230d818586da4686469676573744944046672616e646f6d5820c7ffa307e5de921e67ba5878094787e8807ac8e7b5b3932d2ce80f00f3e9abaf71656c656d656e744964656e7469666965726b6578706972795f646174656c656c656d656e7456616c7565d903ec6a323032342d31302d3230d818586da4686469676573744944076672616e646f6d582026052a42e5880557a806c1459af3fb7eb505d3781566329d0b604b845b5f9e6871656c656d656e744964656e7469666965726f646f63756d656e745f6e756d6265726c656c656d656e7456616c756569313233343536373839d818590471a4686469676573744944086672616e646f6d5820d094dad764a2eb9deb5210e9d899643efbd1d069cc311d3295516ca0b024412d71656c656d656e744964656e74696669657268706f7274726169746c656c656d656e7456616c7565590412ffd8ffe000104a46494600010101009000900000ffdb004300130d0e110e0c13110f11151413171d301f1d1a1a1d3a2a2c2330453d4947443d43414c566d5d4c51685241435f82606871757b7c7b4a5c869085778f6d787b76ffdb0043011415151d191d381f1f38764f434f7676767676767676767676767676767676767676767676767676767676767676767676767676767676767676767676767676ffc00011080018006403012200021101031101ffc4001b00000301000301000000000000000000000005060401020307ffc400321000010303030205020309000000000000010203040005110612211331141551617122410781a1163542527391b2c1f1ffc4001501010100000000000000000000000000000001ffc4001a110101010003010000000000000000000000014111213161ffda000c03010002110311003f00a5bbde22da2329c7d692bc7d0d03f52cfb0ff75e7a7ef3e7709723a1d0dae146ddfbb3c039ce07ad2bd47a7e32dbb8dd1d52d6ef4b284f64a480067dfb51f87ffb95ff00eb9ff14d215de66af089ce44b7dbde9cb6890a2838eddf18078f7add62d411ef4db9b10a65d6b95a147381ea0d495b933275fe6bba75c114104a8ba410413e983dff004f5af5d34b4b4cde632d0bf1fd1592bdd91c6411f3934c2fa6af6b54975d106dcf4a65ae56e856001ebc03c7ce29dd9eef1ef10fc447dc9da76ad2aee93537a1ba7e4f70dd8eff0057c6dffb5e1a19854a83758e54528750946ec6704850cd037bceb08b6d7d2cc76d3317fc7b5cc04fb6707269c5c6e0c5b60ae549242123b0e493f602a075559e359970d98db89525456b51c951c8afa13ea8e98e3c596836783d5c63f5a61a99fdb7290875db4be88ab384bbbbbfc7183fdeaa633e8951db7da396dc48524fb1a8bd611a5aa2a2432f30ab420a7a6d3240c718cf031fa9ef4c9ad550205aa02951df4a1d6c8421b015b769db8c9229837ea2be8b1b0d39d0eba9c51484efdb8c0efd8d258daf3c449699f2edbd4584e7af9c64e3f96b9beb28d4ac40931e6478c8e76a24a825449501d867d2b1dcdebae99b9c752ae4ecd6dde4a179c1c1e460938f9149ef655e515c03919a289cb3dca278fb7bf177f4faa829dd8ce3f2ac9a7ecde490971fafd7dce15eed9b71c018c64fa514514b24e8e4f8c5c9b75c1e82579dc1233dfec08238f6add62d391acc1c5256a79e706d52d431c7a0145140b9fd149eb3a60dc5e88cbbc2da092411e9dc71f39a7766b447b344e847dcac9dcb5abba8d145061d43a6fcf1e65cf15d0e90231d3dd9cfe62995c6dcc5ca12a2c904a15f71dd27d451453e09d1a21450961cbb3ea8a956433b781f1ce33dfed54f0e2b50a2b71d84ed6db18028a28175f74fc6bda105c529a791c25c4f3c7a11f71586268f4a66b726e33de9ea6f1b52b181c760724e47b514520a5a28a283ffd9d81858ffa4686469676573744944096672616e646f6d58204599f81beaa2b20bd0ffcc9aa03a6f985befab3f6beaffa41e6354cdb2ab2ce471656c656d656e744964656e7469666965727264726976696e675f70726976696c656765736c656c656d656e7456616c756582a37576656869636c655f63617465676f72795f636f646561416a69737375655f64617465d903ec6a323031382d30382d30396b6578706972795f64617465d903ec6a323032342d31302d3230a37576656869636c655f63617465676f72795f636f646561426a69737375655f64617465d903ec6a323031372d30322d32336b6578706972795f64617465d903ec6a323032342d31302d32306a697373756572417574688443a10126a118215901f3308201ef30820195a00302010202143c4416eed784f3b413e48f56f075abfa6d87eb84300a06082a8648ce3d04030230233114301206035504030c0b75746f7069612069616361310b3009060355040613025553301e170d3230313030313030303030305a170d3231313030313030303030305a30213112301006035504030c0975746f706961206473310b30090603550406130255533059301306072a8648ce3d020106082a8648ce3d03010703420004ace7ab7340e5d9648c5a72a9a6f56745c7aad436a03a43efea77b5fa7b88f0197d57d8983e1b37d3a539f4d588365e38cbbf5b94d68c547b5bc8731dcd2f146ba381a83081a5301e0603551d120417301581136578616d706c65406578616d706c652e636f6d301c0603551d1f041530133011a00fa00d820b6578616d706c652e636f6d301d0603551d0e0416041414e29017a6c35621ffc7a686b7b72db06cd12351301f0603551d2304183016801454fa2383a04c28e0d930792261c80c4881d2c00b300e0603551d0f0101ff04040302078030150603551d250101ff040b3009060728818c5d050102300a06082a8648ce3d040302034800304502210097717ab9016740c8d7bcdaa494a62c053bbdecce1383c1aca72ad08dbc04cbb202203bad859c13a63c6d1ad67d814d43e2425caf90d422422c04a8ee0304c0d3a68d5903a2d81859039da66776657273696f6e63312e306f646967657374416c676f726974686d675348412d3235366c76616c756544696765737473a2716f72672e69736f2e31383031332e352e31ad00582075167333b47b6c2bfb86eccc1f438cf57af055371ac55e1e359e20f254adcebf01582067e539d6139ebd131aef441b445645dd831b2b375b390ca5ef6279b205ed45710258203394372ddb78053f36d5d869780e61eda313d44a392092ad8e0527a2fbfe55ae0358202e35ad3c4e514bb67b1a9db51ce74e4cb9b7146e41ac52dac9ce86b8613db555045820ea5c3304bb7c4a8dcb51c4c13b65264f845541341342093cca786e058fac2d59055820fae487f68b7a0e87a749774e56e9e1dc3a8ec7b77e490d21f0e1d3475661aa1d0658207d83e507ae77db815de4d803b88555d0511d894c897439f5774056416a1c7533075820f0549a145f1cf75cbeeffa881d4857dd438d627cf32174b1731c4c38e12ca936085820b68c8afcb2aaf7c581411d2877def155be2eb121a42bc9ba5b7312377e068f660958200b3587d1dd0c2a07a35bfb120d99a0abfb5df56865bb7fa15cc8b56a66df6e0c0a5820c98a170cf36e11abb724e98a75a5343dfa2b6ed3df2ecfbb8ef2ee55dd41c8810b5820b57dd036782f7b14c6a30faaaae6ccd5054ce88bdfa51a016ba75eda1edea9480c5820651f8736b18480fe252a03224ea087b5d10ca5485146c67c74ac4ec3112d4c3a746f72672e69736f2e31383031332e352e312e5553a4005820d80b83d25173c484c5640610ff1a31c949c1d934bf4cf7f18d5223b15dd4f21c0158204d80e1e2e4fb246d97895427ce7000bb59bb24c8cd003ecf94bf35bbd2917e340258208b331f3b685bca372e85351a25c9484ab7afcdf0d2233105511f778d98c2f544035820c343af1bd1690715439161aba73702c474abf992b20c9fb55c36a336ebe01a876d6465766963654b6579496e666fa1696465766963654b6579a40102200121582096313d6c63e24e3372742bfdb1a33ba2c897dcd68ab8c753e4fbd48dca6b7f9a2258201fb3269edd418857de1b39a4e4a44b92fa484caa722c228288f01d0c03a2c3d667646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e666fa3667369676e6564c074323032302d31302d30315431333a33303a30325a6976616c696446726f6dc074323032302d31302d30315431333a33303a30325a6a76616c6964556e74696cc074323032312d31302d30315431333a33303a30325a584059e64205df1e2f708dd6db0847aed79fc7c0201d80fa55badcaf2e1bcf5902e1e5a62e4832044b890ad85aa53f129134775d733754d7cb7a413766aeff13cb2e6c6465766963655369676e6564a26a6e616d65537061636573d81841a06a64657669636541757468a1696465766963654d61638443a10105a0f65820e99521a85ad7891b806a07f8b5388a332d92c189a7bf293ee1f543405ae6824d6673746174757300"
        logger.info("Hex binary string inline: ${serializedDoc} (${serializedDoc.javaClass.kotlin}) (size: ${serializedDoc.length})")
        val mdocRespParsed = DeviceResponse.fromCBORHex(serializedDoc)
        val mdoc = mdocRespParsed.documents[0]
        File("mdoc_kotlin.cbor").writeText(serializedDoc)
        assertNotNull(mdoc)

        val bytesCBOR: String = File("mdoc_kotlin.cbor").readText()
        logger.info("Hex binary string read: ${bytesCBOR} (${bytesCBOR.javaClass.kotlin}) (size: ${bytesCBOR.length})")
        //assertTrue(serializedDoc == bytesCBOR)
        val deviceResponse: DeviceResponse = DeviceResponse.Companion.fromCBORHex(bytesCBOR)
        logger.info("deviceResponse: ${deviceResponse}")
        assertNotNull(deviceResponse)
    }

    @Test
    @OptIn(ExperimentalSerializationApi::class)
    fun mdocCBORBuildTest() {
        // Example taken from walt.id: https://github.com/walt-id/waltid-mdoc/tree/main?tab=readme-ov-file#issue-an-mdl-document-to-a-holder
        // Instantiate simple cose crypto provider for issuer keys and certificates
        val ISSUER_KEY_ID = "ISSUER_KEY"
        val DEVICE_KEY_ID = "DEVICE_KEY"
        val kpg = KeyPairGenerator.getInstance("EC")
        var issuerKeyPair: KeyPair = kpg.genKeyPair()
        var deviceKeyPair: KeyPair = kpg.genKeyPair()
        var rootCaKeyPair: KeyPair = kpg.genKeyPair()
        var issuerCertificate: X509Certificate = X509v3CertificateBuilder(X500Name("CN=MDOC ROOT CA"), BigInteger.valueOf(SecureRandom().nextLong()),
            Date(), Date(System.currentTimeMillis() + 24L * 3600 * 1000), X500Name("CN=MDOC Test Issuer"),
            SubjectPublicKeyInfo.getInstance(issuerKeyPair.public.encoded))
            .addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
            .build(JcaContentSignerBuilder("SHA256withECDSA").setProvider(BouncyCastleProvider()).build(rootCaKeyPair.private)).let {
              JcaX509CertificateConverter().setProvider(BouncyCastleProvider()).getCertificate(it) }
        var caCertificate: X509Certificate = X509v3CertificateBuilder(X500Name("CN=MDOC ROOT CA"), BigInteger.valueOf(SecureRandom().nextLong()),
            Date(), Date(System.currentTimeMillis() + 24L * 3600 * 1000), X500Name("CN=MDOC Test Issuer"),
            SubjectPublicKeyInfo.getInstance(issuerKeyPair.public.encoded))
            .addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
            .build(JcaContentSignerBuilder("SHA256withECDSA").setProvider(BouncyCastleProvider()).build(rootCaKeyPair.private)).let {
              JcaX509CertificateConverter().setProvider(BouncyCastleProvider()).getCertificate(it) }
        val cryptoProvider = SimpleCOSECryptoProvider(
        listOf(
            COSECryptoProviderKeyInfo(ISSUER_KEY_ID, AlgorithmID.ECDSA_256, issuerKeyPair.public, issuerKeyPair.private, listOf(issuerCertificate), listOf(caCertificate)),
            COSECryptoProviderKeyInfo(DEVICE_KEY_ID, AlgorithmID.ECDSA_256, deviceKeyPair.public, deviceKeyPair.private)
        )
        )
        // create device key info structure of device public key, for holder binding
        val deviceKeyInfo = DeviceKeyInfo(MapElement(mapOf(MapKey("k") to StringElement("1234"))))

        // build mdoc and sign using issuer key with holder binding to device key
        val mdoc = MDocBuilder("org.iso.18013.5.1.mDL")
        .addItemToSign("org.iso.18013.5.1", "family_name", "Doe".toDataElement())
        .addItemToSign("org.iso.18013.5.1", "given_name", "John".toDataElement())
        .addItemToSign("org.iso.18013.5.1", "birth_date", FullDateElement(LocalDate(1990, 1, 15)))
        .sign(ValidityInfo(Clock.System.now(), Clock.System.now(), Clock.System.now()),
            deviceKeyInfo, cryptoProvider, ISSUER_KEY_ID,
            StatusElement(StatusListInfo(6441u, "https://issuer-openid4vc.ssi.tir.budru.de/status-list/0ced6204-ed17-41f4-a1a5-6a772cb3d263"))
        )
        val deviceResponse: DeviceResponse = DeviceResponse(documents = listOf(mdoc))
        logger.info("mdoc: ${mdoc}")
        logger.info("mdoc: ${mdoc.MSO}")
        logger.info("SIGNED MDOC:")
        logger.info(Cbor.encodeToHexString(mdoc))
        logger.info("deviceResponse: ${deviceResponse}")
        assertNotNull(mdoc)

        File("mdoc_kotlin_status_list_valid.cbor").writeText(deviceResponse.toCBORHex())
        val hexString: String = File("mdoc_kotlin_status_list_valid.cbor").readText()
        val deviceResponseRead: DeviceResponse = DeviceResponse.Companion.fromCBORHex(hexString)
        logger.info("deviceResponse: ${deviceResponseRead}")
    }

}