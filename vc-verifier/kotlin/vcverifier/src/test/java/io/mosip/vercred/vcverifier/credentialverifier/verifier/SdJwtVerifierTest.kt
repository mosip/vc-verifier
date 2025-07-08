package io.mosip.vercred.vcverifier.credentialverifier.verifier

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.springframework.util.ResourceUtils
import java.nio.file.Files

class SdJwtVerifierTest{

    @Test
    fun `should verify sd-jwt successfully`() {

        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "sd-jwt_vc/sdJwt.txt")
        val vc = String(Files.readAllBytes(file.toPath()))

        assertTrue( SdJwtVerifier().verify(vc))
    }

    @Test
    fun `should return false for tampered sd-jwt`() {

        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "sd-jwt_vc/invalidSdJwt.txt")
        val vc = String(Files.readAllBytes(file.toPath()))

        assertFalse( SdJwtVerifier().verify(vc))
    }
}