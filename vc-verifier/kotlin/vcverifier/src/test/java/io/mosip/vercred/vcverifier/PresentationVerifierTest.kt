package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_CODE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_MESSAGE_VERIFICATION_FAILED
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.concurrent.TimeUnit

class PresentationVerifierTest {

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return true for valid presentation verification success`() {
        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/Ed25519Signature2018SignedVP-didKey.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = PresentationVerifier().verify(vc)

        assertTrue(verificationResult.verificationStatus)
        assertEquals("", verificationResult.verificationMessage)
        assertEquals("", verificationResult.verificationErrorCode)

    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return false for invalid presentation verification`() {
        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/InvalidEd25519Signature2018SignedVP-didKey.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = PresentationVerifier().verify(vc)

        assertFalse(verificationResult.verificationStatus)
        assertEquals(ERROR_MESSAGE_VERIFICATION_FAILED, verificationResult.verificationMessage)
        assertEquals(ERROR_CODE_VERIFICATION_FAILED, verificationResult.verificationErrorCode)

    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should throw error when public key not found false`() {
        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/InvalidPublicKeyEd25519Signature2018SignedVP-didKey.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        assertThrows<IllegalStateException> { PresentationVerifier().verify(vc) }
    }
}