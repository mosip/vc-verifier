package io.mosip.vercred.vcverifier.credentialverifier.verifier

import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkConstructor
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions
import io.mosip.vercred.vcverifier.exception.DidResolverExceptions.UnsupportedDidUrl
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import foundation.identity.jsonld.JsonLDObject


class LdpVerifierTest {

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should return true for valid ps256 credential`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/PS256SignedMosipVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        assertTrue(LdpVerifier().verify(vc))
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should return false for invalid credential`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/tamperedVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        assertFalse(LdpVerifier().verify(vc))
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should successfully verify valid sunbird credential`(){
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/Ed25519Signature2020SignedSunbirdVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        assertTrue(LdpVerifier().verify(vc))
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should throw error if did url is not valid while verify valid sunbird credential`(){
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/InvalidDidUrlSunbirdVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        val exception = assertThrows<PublicKeyNotFoundException> {
            LdpVerifier().verify(vc)
        }
        assertEquals("Given did url is not supported", exception.message)
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should successfully verify valid ed25519Signature2018 signed credential with did verification method`(){
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/Ed25519Signature2018SignedVC-did.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        assertTrue(LdpVerifier().verify(vc))
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should successfully verify valid ed25519Signature2018 signed credential with https verification method`(){
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/Ed25519Signature2018SignedVC-https.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        assertTrue(LdpVerifier().verify(vc))
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should successfully verify valid rs256 credential`(){
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/RS256SignedMosipVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))
        assertTrue(LdpVerifier().verify(vc))
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should return false for unrevoked credential`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/vcUnrevoked-https.json")
        val vcJson = String(Files.readAllBytes(file.toPath()))
        val jsonLdObject = JsonLDObject.fromJson(vcJson)

        mockkConstructor(StatusListRevocationChecker::class)
        every { anyConstructed<StatusListRevocationChecker>().isRevoked(jsonLdObject) } returns false

        val result = StatusListRevocationChecker().isRevoked(jsonLdObject)
        assertFalse(result, "Expected credential to be not revoked")
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should return true for revoked credential`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/vcRevoked-https.json")
        val vcJson = String(Files.readAllBytes(file.toPath()))
        val jsonLdObject = JsonLDObject.fromJson(vcJson)

        mockkConstructor(StatusListRevocationChecker::class)
        every { anyConstructed<StatusListRevocationChecker>().isRevoked(jsonLdObject) } returns true

        val result = StatusListRevocationChecker().isRevoked(jsonLdObject)
        assertTrue(result, "Expected credential to be revoked")
    }

}