package io.mosip.vercred.vcverifier.publicKey.impl

import com.nimbusds.jose.jwk.JWK
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.publicKey.PublicKeyGetter
import io.mosip.vercred.vcverifier.utils.Base64Decoder
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.net.URI
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec


class DidJwkPublicKeyGetter : PublicKeyGetter {
    private var provider: BouncyCastleProvider = BouncyCastleProvider()
    private var b64Decoder: Base64Decoder = Base64Decoder()
    override fun get(verificationMethod: URI): PublicKey {

        try {
            val jwk: JWK = JWK.parse(
                String(
                    b64Decoder.decodeFromBase64UrlFormatEncoded(
                        verificationMethod.toString().split("did:jwk:")[1]
                    )
                )
            )
            val publicKeyBytes =
                b64Decoder.decodeFromBase64UrlFormatEncoded(jwk.toOctetKeyPair().x.toString())
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