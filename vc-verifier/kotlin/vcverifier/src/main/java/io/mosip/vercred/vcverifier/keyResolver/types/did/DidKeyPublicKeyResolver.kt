package io.mosip.vercred.vcverifier.keyResolver.types.did

import io.ipfs.multibase.Multibase
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.exception.PublicKeyTypeNotSupportedException
import io.mosip.vercred.vcverifier.exception.UnknownException
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays

private const val MULTIBASE_KEY_SIZE = 34
private const val ED_KEY_PREFIX = 0xed.toByte()
private const val MULTICODEC_TRAILING_BYTE = 0x01.toByte()

class DidKeyPublicKeyResolver : DidPublicKeyResolver() {
    private val provider: BouncyCastleProvider = BouncyCastleProvider()

    override fun extractPublicKey(parsedDID: ParsedDID, keyId: String?): PublicKey {
        val decodedKey =
            Multibase.decode(
                parsedDID.id
            )
        if (isEd25519KeyType(decodedKey)) {
            try {

                val publicKeyBytes = Arrays.copyOfRange(decodedKey, 2, MULTIBASE_KEY_SIZE)
                val algorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
                val subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithmIdentifier, publicKeyBytes)
                val encodedKey = subjectPublicKeyInfo.encoded
                val keySpec = X509EncodedKeySpec(encodedKey)
                val keyFactory = KeyFactory.getInstance(JWS_EDDSA_SIGN_ALGO_CONST, provider)
                return keyFactory.generatePublic(keySpec)
            } catch (e: Exception) {
                when (e) {
                    is IllegalStateException,
                    is InvalidKeySpecException,
                    is IllegalArgumentException -> throw e

                    else -> {
                        throw UnknownException("Error while getting public key object - "+e.message)
                    }
                }
            }
        } else {
            throw PublicKeyTypeNotSupportedException(message = "KeyType - ${decodedKey[0]} is not supported. Supported: ed25519")
        }
    }

    private fun isEd25519KeyType(decodedKey: ByteArray) =
        (decodedKey[0] == ED_KEY_PREFIX && decodedKey[1] == MULTICODEC_TRAILING_BYTE) && decodedKey.size == MULTIBASE_KEY_SIZE
}