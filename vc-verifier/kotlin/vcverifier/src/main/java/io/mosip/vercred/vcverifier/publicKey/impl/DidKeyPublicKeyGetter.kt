import io.ipfs.multibase.Multibase
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.JWS_EDDSA_SIGN_ALGO_CONST
import io.mosip.vercred.vcverifier.exception.SignatureNotSupportedException
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.publicKey.PublicKeyGetter
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.net.URI
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays


class DidKeyPublicKeyGetter : PublicKeyGetter {
    private var provider: BouncyCastleProvider = BouncyCastleProvider()
    override fun get(verificationMethod: URI): PublicKey {

        val decodedKey =
            Multibase.decode(
                verificationMethod.toString()
                    .split("#".toRegex())
                    .first()
                    .split("did:key:".toRegex())
                    .dropLastWhile { it.isEmpty() }
                    .toTypedArray()[1]
            )
        //The below check is for ed25519 keys as ed25519 is only supported for now
        if ((decodedKey[0] == 0xed.toByte() && decodedKey[1] == 0x01.toByte()) && decodedKey.size == 34) {
            try {

                val publicKeyBytes = Arrays.copyOfRange(decodedKey, 2, 34)
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
                        throw UnknownException("Error while getting public key object")
                    }
                }
            }
        } else {
            throw SignatureNotSupportedException("Unsupported jws signature algorithm")
        }
    }
}