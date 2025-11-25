package testutils

import io.mockk.every
import io.mosip.vercred.vcverifier.CredentialsVerifierTest
import io.mosip.vercred.vcverifier.networkManager.NetworkManagerClient
import org.springframework.util.ResourceUtils
import java.nio.file.Files

fun readClasspathFile(path: String): String =
    String(Files.readAllBytes(ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + path).toPath()))

fun mockHttpResponse(credentialsVerifierTest: CredentialsVerifierTest, url: String, responseJson: String) {
    every { NetworkManagerClient.Companion.sendHTTPRequest(url, any()) } answers {
        credentialsVerifierTest.mapper.readValue(responseJson, Map::class.java) as Map<String, Any>?
    }
}