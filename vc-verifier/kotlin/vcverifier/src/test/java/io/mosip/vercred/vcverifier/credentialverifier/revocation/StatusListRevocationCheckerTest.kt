package io.mosip.vercred.vcverifier.credentialverifier.revocation

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer


class StatusListRevocationCheckerTest {
    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should return false for revocation which doesnt contains the credential Status`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/PS256SignedMosipVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val revocationChecker: RevocationChecker = StatusListRevocationChecker()
        val isRevoked = revocationChecker.isRevoked(vc)

        assertFalse(isRevoked)
    }

    @Test
    fun `should return true with mocked statusListCredential url with revoked status`() {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("""{"status":"revoked"}""")
        )
        server.start()

        val mockBaseUrl = server.url("/revocation-list").toString()

        // Replace statusListCredential in test VC with mock URL
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/vcRevoked-https.json")
        var vc = String(Files.readAllBytes(file.toPath()))
        vc = vc.replace(
            Regex(""""statusListCredential"\s*:\s*".*?""""),
            """"statusListCredential": "$mockBaseUrl""""
        )

        val checker = StatusListRevocationChecker()
        val isRevoked = checker.isRevoked(vc)

        assertTrue(isRevoked)

        server.shutdown()
    }

    @Test
    fun `should return false with mocked statusListCredential url with valid status`() {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody("""{"status":"valid"}""")
        )
        server.start()

        val mockBaseUrl = server.url("/revocation-list").toString()

        // Replace statusListCredential in test VC with mock URL
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/vcRevoked-https.json")
        var vc = String(Files.readAllBytes(file.toPath()))
        vc = vc.replace(
            Regex(""""statusListCredential"\s*:\s*".*?""""),
            """"statusListCredential": "$mockBaseUrl""""
        )

        val checker = StatusListRevocationChecker()
        val isRevoked = checker.isRevoked(vc)

        assertFalse(isRevoked)

        server.shutdown()
    }

}