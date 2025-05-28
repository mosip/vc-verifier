package io.mosip.vercred.vcverifier.publicKey.impl

import android.os.Build
import androidx.annotation.RequiresApi
import com.nimbusds.jose.jwk.JWK
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
import java.util.Base64

@RequiresApi(Build.VERSION_CODES.O)
class DidJwkPublicKeyGetter : PublicKeyGetter {
    private var provider: BouncyCastleProvider = BouncyCastleProvider()
    override fun get(verificationMethod: URI): PublicKey {

        try {
            val jwk: JWK = JWK.parse(
                String(
                    Base64.getUrlDecoder()
                        .decode(verificationMethod.toString().split("did:jwk:")[1])
                )
            )
            val publicKeyBytes = Base64.getUrlDecoder().decode(jwk.toOctetKeyPair().x.toString())
            val algorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
            val subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithmIdentifier, publicKeyBytes)
            val encodedKey = subjectPublicKeyInfo.encoded
            val keySpec = X509EncodedKeySpec(encodedKey)
            val keyFactory = KeyFactory.getInstance("EdDSA", provider)
            return keyFactory.generatePublic(keySpec)
        } catch (e: Exception) {
            when (e) {
                is IllegalArgumentException,
                is InvalidKeySpecException -> throw e

                else -> {
                    throw UnknownException("Error while getting public key object")
                }
            }
        }
    }
}