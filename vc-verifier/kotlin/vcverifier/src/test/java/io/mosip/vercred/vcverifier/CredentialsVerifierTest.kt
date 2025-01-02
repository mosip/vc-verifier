package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.constants.CredentialFormat.LDP_VC
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CONTEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_CODE_VERIFICATION_FAILED
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.concurrent.TimeUnit


class CredentialsVerifierTest {

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should return true for valid credential validation success`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "VC/PS256SignedMosipVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = CredentialsVerifier().verify(vc, LDP_VC)

        assertEquals("", verificationResult.verificationMessage)
        assertTrue(verificationResult.verificationStatus)
        assertEquals("", verificationResult.verificationErrorCode)
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should return false for invalid credential validation failure`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "VC/invalidVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = CredentialsVerifier().verify(vc, LDP_VC)

        assertFalse(verificationResult.verificationStatus)
        assertEquals("${ERROR_CODE_MISSING}${CONTEXT.uppercase()}", verificationResult.verificationErrorCode)
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should return true for valid credential verification success`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "VC/PS256SignedMosipVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = CredentialsVerifier().verify(vc, LDP_VC)

        assertEquals("", verificationResult.verificationMessage)
        assertTrue(verificationResult.verificationStatus)
        assertEquals("", verificationResult.verificationErrorCode)

    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should return false for invalid credential verification failure`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "VC/tamperedVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verify = CredentialsVerifier().verify(vc, LDP_VC)

        assertFalse(verify.verificationStatus)
        assertEquals(ERROR_CODE_VERIFICATION_FAILED, verify.verificationErrorCode)
    }
}