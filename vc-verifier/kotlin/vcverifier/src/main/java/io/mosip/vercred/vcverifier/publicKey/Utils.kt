package io.mosip.vercred.vcverifier.publicKey

import io.ipfs.multibase.Base58
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.DER_PUBLIC_KEY_PREFIX
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2018
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_KEY_TYPE
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.io.pem.PemReader
import java.io.StringReader
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec


private var provider: BouncyCastleProvider = BouncyCastleProvider()

fun isPublicKeyMultibase(publicKeyMultibase: String): Boolean {
    val rawPublicKeyWithHeader = Base58.decode(publicKeyMultibase.substring(1))
    return rawPublicKeyWithHeader.size > 2 &&
            rawPublicKeyWithHeader[0] == 0xed.toByte() &&
            rawPublicKeyWithHeader[1] == 0x01.toByte()
}

fun isPemPublicKey(str: String) = str.contains("BEGIN PUBLIC KEY")

private val PUBLIC_KEY_ALGORITHM: Map<String, String> = mapOf(
    RSA_KEY_TYPE to RSA_ALGORITHM,
    ED25519_KEY_TYPE_2018 to ED25519_ALGORITHM,
    ED25519_KEY_TYPE_2020 to ED25519_ALGORITHM
)

fun getPublicKeyObjectFromPemPublicKey(publicKeyPem: String, keyType: String): PublicKey {
    try {
        val strReader = StringReader(publicKeyPem)
        val pemReader = PemReader(strReader)
        val pemObject = pemReader.readPemObject()
        val pubKeyBytes = pemObject.content
        val pubKeySpec = X509EncodedKeySpec(pubKeyBytes)
        val keyFactory = KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM[keyType], provider)
        return keyFactory.generatePublic(pubKeySpec)
    } catch (e: Exception) {
        //logger.severe("Error Generating public key object$e")
        throw PublicKeyNotFoundException("Public key object is null")
    }
}

fun getPublicKeyObjectFromPublicKeyMultibase(publicKeyPem: String, keyType: String): PublicKey {
    try {
        val rawPublicKeyWithHeader = Base58.decode(publicKeyPem.substring(1))
        val rawPublicKey = rawPublicKeyWithHeader.copyOfRange(2, rawPublicKeyWithHeader.size)
        val publicKey = Hex.decode(DER_PUBLIC_KEY_PREFIX) + rawPublicKey

        val pubKeySpec = X509EncodedKeySpec(publicKey)
        val keyFactory = KeyFactory.getInstance(PUBLIC_KEY_ALGORITHM[keyType], provider)
        return keyFactory.generatePublic(pubKeySpec)
    } catch (e: Exception) {
        //logger.severe("Error Generating public key object$e")
        throw PublicKeyNotFoundException("Public key object is null")
    }
}

