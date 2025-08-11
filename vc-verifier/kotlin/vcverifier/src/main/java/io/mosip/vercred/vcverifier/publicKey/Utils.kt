package io.mosip.vercred.vcverifier.publicKey

import com.fasterxml.jackson.databind.ObjectMapper
import io.ipfs.multibase.Base58
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.COMPRESSED_HEX_KEY_LENGTH
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.DER_PUBLIC_KEY_PREFIX
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2018
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ED25519_KEY_TYPE_2020
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ES256K_KEY_TYPE_2019
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWK_KEY_TYPE_EC
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.RSA_KEY_TYPE
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.SECP256K1
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import io.mosip.vercred.vcverifier.exception.PublicKeyResolutionFailedException
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.utils.Base64Decoder
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
import java.util.logging.Logger

private val base64Decoder = Base64Decoder()

private val logger = Logger.getLogger("KeyResolverUtils")


private var provider: BouncyCastleProvider = BouncyCastleProvider()

private val PUBLIC_KEY_ALGORITHM: Map<String, String> = mapOf(
    RSA_KEY_TYPE to RSA_ALGORITHM,
    ED25519_KEY_TYPE_2018 to ED25519_ALGORITHM,
    ED25519_KEY_TYPE_2020 to ED25519_ALGORITHM,
)

private const val SECP256K1_PRIME_MODULUS =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"

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


fun getPublicKeyFromJWK(jwkStr: String, keyType: String): PublicKey {
    val objectMapper = ObjectMapper()
    val jwk: Map<String, String> =
        objectMapper.readValue(jwkStr, Map::class.java) as Map<String, String>

    return when (keyType) {
        ES256K_KEY_TYPE_2019 -> getECPublicKey(jwk)
        ED25519_KEY_TYPE_2020 -> getEdPublicKey(jwk)
        else -> throw PublicKeyTypeNotSupportedException("Unsupported key type: $keyType")
    }
}

private const val X509_HEADER_PREFIX = "MCowBQYDK2VwAyEA"

internal fun getEdPublicKey(jwk: Map<String, String>): PublicKey {
    val keyType = jwk["kty"]
    require(keyType == "OKP") { throw  PublicKeyResolutionFailedException("KeyType - $keyType is not supported. Supported: OKP")}
    val curve = jwk["crv"]
    require(curve == "Ed25519") { throw PublicKeyResolutionFailedException("Curve - $curve is not supported. Supported: Ed25519") }

    val xB64Url = jwk["x"] ?: throw PublicKeyResolutionFailedException("Missing the public key data in JWK")
    val xBytes = base64Decoder.decodeFromBase64Url(xB64Url)

    // Wrap in X.509 SubjectPublicKeyInfo for Ed25519
    val x509HeaderPrefixB64Decoded = base64Decoder.decodeFromBase64Url(X509_HEADER_PREFIX)
    val spki = x509HeaderPrefixB64Decoded + xBytes

    val keySpec = X509EncodedKeySpec(spki)
    return KeyFactory.getInstance("Ed25519").generatePublic(keySpec)
}


private fun getECPublicKey(jwk: Map<String, String>): PublicKey {
    val curve = jwk["crv"] ?: throw IllegalArgumentException("Missing 'crv' field for EC key")
    val xBytes = Base64Decoder().decodeFromBase64Url(jwk["x"]!!)
    val yBytes = Base64Decoder().decodeFromBase64Url(jwk["y"]!!)

    val x = BigInteger(1, xBytes)
    val y = BigInteger(1, yBytes)
    val ecPoint = java.security.spec.ECPoint(x, y)

    val ecSpec = when (curve) {
        SECP256K1 -> ECNamedCurveTable.getParameterSpec(SECP256K1)
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

fun getPublicKeyFromHex(hexKey: String, keyType: String): PublicKey {
    return when (keyType) {
        ES256K_KEY_TYPE_2019 -> getECPublicKeyFromHex(hexKey)
        else -> throw PublicKeyTypeNotSupportedException("Unsupported key type: $keyType")
    }
}

fun getECPublicKeyFromHex(hexKey: String): PublicKey {
    val keyFactory = KeyFactory.getInstance(JWK_KEY_TYPE_EC, provider)
    val keyBytes = hexStringToByteArray(hexKey)
    val ecPoint = decodeSecp256k1PublicKey(keyBytes)
    val ecSpec = secp256k1Params()
    val pubKeySpec = ECPublicKeySpec(ecPoint, ecSpec)

    return keyFactory.generatePublic(pubKeySpec) as ECPublicKey
}

private fun hexStringToByteArray(hex: String): ByteArray {
    return BigInteger(hex, 16).toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
}


private fun decodeSecp256k1PublicKey(keyBytes: ByteArray): java.security.spec.ECPoint {
    require(keyBytes.size == COMPRESSED_HEX_KEY_LENGTH) { "Invalid compressed public key length" }

    val x = BigInteger(1, keyBytes.copyOfRange(1, keyBytes.size))
    val y = recoverYCoordinate(x, keyBytes[0] == 3.toByte())

    return java.security.spec.ECPoint(x, y)
}

// Recover the Y-coordinate from X using the Secp256k1 curve equation
private fun recoverYCoordinate(x: BigInteger, odd: Boolean): BigInteger {
    val p = BigInteger(SECP256K1_PRIME_MODULUS, 16)
    val b = BigInteger.valueOf(7)

    val rhs = (x.modPow(BigInteger.valueOf(3), p).add(b)).mod(p)
    val y = rhs.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p)

    return if (y.testBit(0) == odd) y else p.subtract(y)
}

private fun secp256k1Params(): ECParameterSpec {
    val params = ECNamedCurveTable.getParameterSpec(SECP256K1)
    return ECNamedCurveSpec(SECP256K1, params.curve, params.g, params.n, params.h)
}



