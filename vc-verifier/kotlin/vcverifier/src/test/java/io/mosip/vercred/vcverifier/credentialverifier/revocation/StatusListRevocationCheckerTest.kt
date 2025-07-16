package io.mosip.vercred.vcverifier.credentialverifier.revocation

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class StatusListRevocationCheckerTest {
    @Test
    fun `should return false when VC is not revoked`() {
        val revokedVcFile = ResourceUtils.getFile("classpath:ldp_vc/vcUnrevoked-https.json")
        var vcJson = String(Files.readAllBytes(revokedVcFile.toPath()))

        val statusListFile = ResourceUtils.getFile("classpath:ldp_vc/status-list-vc.json")
        val statusListJson = String(Files.readAllBytes(statusListFile.toPath()))

        val server = MockWebServer().apply {
            enqueue(MockResponse().setResponseCode(200).setBody(statusListJson))
            start()
        }

        val mockBaseUrl = server.url("/revocation-list").toString()

        vcJson = vcJson.replace(
            Regex(""""statusListCredential"\s*:\s*".*?""""),
            """"statusListCredential": "$mockBaseUrl""""
        )

        val revocationChecker = LdpRevokeChecker()
        val isRevoked = revocationChecker.isRevoked(vcJson)
        assertFalse(isRevoked)
        server.shutdown()
    }

    @Test
    fun `should return true when VC is revoked`() {
        val revokedVcFile = ResourceUtils.getFile("classpath:ldp_vc/vcRevoked-https.json")
        var vcJson = String(Files.readAllBytes(revokedVcFile.toPath()))

        val statusListFile = ResourceUtils.getFile("classpath:ldp_vc/status-list-vc.json")
        val statusListJson = String(Files.readAllBytes(statusListFile.toPath()))

        val server = MockWebServer().apply {
            enqueue(MockResponse().setResponseCode(200).setBody(statusListJson))
            start()
        }

        val mockBaseUrl = server.url("/revocation-list").toString()

        vcJson = vcJson.replace(
            Regex(""""statusListCredential"\s*:\s*".*?""""),
            """"statusListCredential": "$mockBaseUrl""""
        )

        val revocationChecker = LdpRevokeChecker()
        val isRevoked = revocationChecker.isRevoked(vcJson)
        assertTrue(isRevoked)
        server.shutdown()
    }

    @Test
    fun `should return false when credentialStatus is missing`() {
        val file = ResourceUtils.getFile("classpath:ldp_vc/PS256SignedMosipVC.json") 
        val vc = String(Files.readAllBytes(file.toPath()))

        val checker = LdpRevokeChecker()
        val isRevoked = checker.isRevoked(vc)
        assertFalse(isRevoked)
    }

    @Test
    fun `should throw exception for invalid statusListCredential url`() {
        val file = ResourceUtils.getFile("classpath:ldp_vc/vcRevoked-https.json")
        var vc = String(Files.readAllBytes(file.toPath()))

        // Inject invalid URL in credentialStatus
        vc = vc.replace(
            Regex(""""statusListCredential"\s*:\s*".*?""""),
            """"statusListCredential": "http://localhost:9999/invalid-url""""
        )

        val checker = LdpRevokeChecker()

        val exception = assertThrows<RuntimeException> {
            checker.isRevoked(vc)
        }
        val msg = exception.message!!
        assert(msg.contains("Failed to check revocation"))
    }
    @Test
    fun `should throw exception when credentialStatus type is missing`() {
        val file = ResourceUtils.getFile("classpath:ldp_vc/vcUnrevoked-https.json")
        var vc = String(Files.readAllBytes(file.toPath()))

        // Remove 'type' field from credentialStatus
        vc = vc.replace(
            Regex(""""type"\s*:\s*".*?",?\s*"""),
            ""
        )

        val checker = LdpRevokeChecker()
        val exception = assertThrows<IllegalArgumentException> {
            checker.isRevoked(vc)
        }
        assert(exception.message!!.contains("Missing or empty 'type'"))
    }

    @Test
    fun `should throw exception when credentialStatus type is empty`() {
        val file = ResourceUtils.getFile("classpath:ldp_vc/vcUnrevoked-https.json")
        var vc = String(Files.readAllBytes(file.toPath()))

        // Replace 'type' field with an empty string
        vc = vc.replace(
            Regex(""""type"\s*:\s*".*?""""),
            """"type": """""
        )

        val checker = LdpRevokeChecker()
        val exception = assertThrows<IllegalArgumentException> {
            checker.isRevoked(vc)
        }
        assert(exception.message!!.contains("Missing or empty 'type'"))
    }


}