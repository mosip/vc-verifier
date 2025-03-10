package io.mosip.vercred.vcverifier.publicKey

import com.fasterxml.jackson.databind.ObjectMapper
import io.ipfs.multibase.Base58
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.DER_PUBLIC_KEY_PREFIX
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2018
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWK_KEY_TYPE_EC
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_KEY_TYPE
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.utils.Encoder
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.util.encoders.Hex
import org.bouncycastle.util.io.pem.PemReader
import java.io.StringReader
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECParameterSpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.X509EncodedKeySpec

private var provider: BouncyCastleProvider = BouncyCastleProvider()

fun isPublicKeyMultibase(publicKeyMultibase: String): Boolean {
    //ref: https://w3c.github.io/vc-di-eddsa/#multikey
    val rawPublicKeyWithHeader = Base58.decode(publicKeyMultibase.substring(1))
    return rawPublicKeyWithHeader.size > 2 &&
            rawPublicKeyWithHeader[0] == 0xed.toByte() &&
            rawPublicKeyWithHeader[1] == 0x01.toByte()
}

fun isPemPublicKey(str: String) = str.contains("BEGIN PUBLIC KEY")

fun isPublicKeyJwk(publicKeyStr: String): Boolean {
    return publicKeyStr.contains("\"kty\"")
}

fun isPublicKeyHex(publicKeyStr: String): Boolean {
    // check only hexadecimal characters are present.
    val hexRegex = Regex("^[0-9a-fA-F]+$")

    // Check if the string matches hex format and has valid length (33 or 65 bytes in hex)
    return publicKeyStr.matches(hexRegex) &&
            (publicKeyStr.length == 66) &&
            (publicKeyStr.startsWith("02") || publicKeyStr.startsWith("03"))
}

private val PUBLIC_KEY_ALGORITHM: Map<String, String> = mapOf(
    RSA_KEY_TYPE to RSA_ALGORITHM,
    ED25519_KEY_TYPE_2018 to ED25519_ALGORITHM,
    ED25519_KEY_TYPE_2020 to ED25519_ALGORITHM,
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
        throw PublicKeyNotFoundException("Public key object is null")
    }
}


fun getPublicKeyFromJWK(jwkStr: String): PublicKey {
    try {
        val objectMapper = ObjectMapper()
        val jwk: Map<String, String> = objectMapper.readValue(jwkStr, Map::class.java) as Map<String, String>

        val keyType = jwk["kty"] ?: throw IllegalArgumentException("Missing 'kty' field in JWK")

        return when (keyType) {
            JWK_KEY_TYPE_EC -> getECPublicKey(jwk)
            //"RSA" -> getRSAPublicKey(jwk)
            //"OKP" -> getOKPPublicKey(jwk)
            else -> throw PublicKeyTypeNotSupportedException("Unsupported key type: $keyType")
        }
    } catch (e: Exception) {
        throw IllegalArgumentException("Failed to convert JWK to PublicKey: ${e.message}")
    }
}

fun getECPublicKey(jwk: Map<String, String>): PublicKey {
    val curve = jwk["crv"] ?: throw IllegalArgumentException("Missing 'crv' field for EC key")
    val xBytes = Encoder().decodeFromBase64UrlFormatEncoded(jwk["x"]!!)
    val yBytes = Encoder().decodeFromBase64UrlFormatEncoded(jwk["y"]!!)

    val x = BigInteger(1, xBytes)
    val y = BigInteger(1, yBytes)
    val ecPoint = java.security.spec.ECPoint(x, y)

    val ecSpec = when (curve){
        "secp256k1" -> ECNamedCurveTable.getParameterSpec("secp256k1")
        //"secp256r1" -> ECNamedCurveTable.getParameterSpec("secp256r1")
        else -> throw IllegalArgumentException("Unsupported EC curve: $curve")
    }

    val ecParameterSpec = ECNamedCurveSpec(curve, ecSpec.curve, ecSpec.g, ecSpec.n)
    val pubKeySpec = ECPublicKeySpec(ecPoint, ecParameterSpec)
    val keyFactory = KeyFactory.getInstance(JWK_KEY_TYPE_EC, provider)
    return keyFactory.generatePublic(pubKeySpec)
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
        throw PublicKeyNotFoundException("Public key object is null")
    }
}

fun getPublicKeyFromHex(hexKey: String): PublicKey {
    val keyFactory = KeyFactory.getInstance(JWK_KEY_TYPE_EC, provider)
    val keyBytes = hexStringToByteArray(hexKey)
    val ecPoint = decodeSecp256k1PublicKey(keyBytes)


    val ecSpec = secp256k1Params()
    val pubKeySpec = ECPublicKeySpec(ecPoint, ecSpec)

    return keyFactory.generatePublic(pubKeySpec) as ECPublicKey
}

fun hexStringToByteArray(hex: String): ByteArray {
    return BigInteger(hex, 16).toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
}

fun decodeSecp256k1PublicKey(keyBytes: ByteArray): java.security.spec.ECPoint {
    require(keyBytes.size == 33) { "Invalid compressed public key length" }

    val x = BigInteger(1, keyBytes.copyOfRange(1, keyBytes.size))
    val y = recoverYCoordinate(x, keyBytes[0] == 3.toByte())

    return java.security.spec.ECPoint(x, y)
}

// Recover the Y-coordinate from X using the Secp256k1 curve equation
fun recoverYCoordinate(x: BigInteger, odd: Boolean): BigInteger {
    val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    val a = BigInteger.ZERO
    val b = BigInteger.valueOf(7)

    val rhs = (x.modPow(BigInteger.valueOf(3), p).add(b)).mod(p)
    val y = rhs.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p)

    return if (y.testBit(0) == odd) y else p.subtract(y)
}

fun secp256k1Params(): ECParameterSpec {
    val params = ECNamedCurveTable.getParameterSpec("secp256k1")
    return ECNamedCurveSpec("secp256k1", params.curve, params.g, params.n, params.h)
}



