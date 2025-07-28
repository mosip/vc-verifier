package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.data.VPVerificationStatus
import io.mosip.vercred.vcverifier.data.VerificationStatus
import org.junit.Ignore
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.assertThrows
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.concurrent.TimeUnit

class PresentationVerifierTest {

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return true for valid presentation verification success Ed25519Signature2018`() {
        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/Ed25519Signature2018SignedVP-didKey.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = PresentationVerifier().verify(vc)

        assertEquals(VPVerificationStatus.VALID,verificationResult.proofVerificationStatus)
        //check when we have a supported vc
        //assertEquals(verificationResult.vcResults, emptyList<VCResult>())

    }

    @Ignore("Skipping this test ")
    fun `should return true for valid presentation verification success JsonWebSignature2020`() {
        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/JsonWebSignature2020SignedVP-didJws.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = PresentationVerifier().verify(vc)

        assertEquals(VPVerificationStatus.VALID,verificationResult.proofVerificationStatus)
        assertEquals(verificationResult.vcResults[0].status, VerificationStatus.SUCCESS)
        assertNotEquals(verificationResult.vcResults[0].vc, "")
        assertNotNull(verificationResult.vcResults[0].vc)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return false for invalid presentation verification`() {
        val file =
            ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "vp/InvalidEd25519Signature2018SignedVP-didKey.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = PresentationVerifier().verify(vc)
        assertEquals(VPVerificationStatus.INVALID,verificationResult.proofVerificationStatus)
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