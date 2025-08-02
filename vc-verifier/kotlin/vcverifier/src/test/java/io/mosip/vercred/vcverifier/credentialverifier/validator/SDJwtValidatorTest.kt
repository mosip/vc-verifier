package io.mosip.vercred.vcverifier.credentialverifier.validator


import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.*
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class SdJwtValidatorTest {

    private val validator = SdJwtValidator()

    private fun loadSampleSdJwt(fileName: String): String {
        val file = ResourceUtils.getFile("classpath:sd-jwt_vc/$fileName")
        return String(Files.readAllBytes(file.toPath()))
    }

    private fun modifySdJwtPayload(sdJwt: String, modify: (JSONObject) -> Unit): String {
        val parts = sdJwt.split("~")
        val jwtParts = parts[0].split(".")
        val header = jwtParts[0]
        val payload = jwtParts[1]
        val signature = jwtParts[2]

        val payloadJson = JSONObject(String(Base64.getUrlDecoder().decode(payload)))
        modify(payloadJson)

        val modifiedPayload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.toString().toByteArray())

        val newJwt = listOf(header, modifiedPayload, signature).joinToString(".")
        return listOf(newJwt).plus(parts.drop(1)).joinToString("~")
    }

    private fun getDisclosureTamperedSdJWT(): String{
        val vc = loadSampleSdJwt("sdJwtAnimo.txt")
        val parts = vc.split("~").toMutableList()
        val tamperedDisclosure = "WyI1ODE3OTQ1NTIzMDA0NzQwMDYwNTU3OTQiLCJpc3N1aW5nX2NvdW50cnkiLCJJTiJd"
        parts[parts.lastIndex - 1] = tamperedDisclosure
        return parts.joinToString("~")
    }


    @Test
    fun `should validate a valid SD-JWT VC successfully`() {
        var vc = loadSampleSdJwt("sdJwtAnimo.txt")
        var status = validator.validate(vc)
        assertEquals("", status.validationMessage)
        assertEquals("", status.validationErrorCode)
        vc = loadSampleSdJwt("sdJwtAnimoCOR.txt")
        status = validator.validate(vc)
        assertEquals("", status.validationMessage)
        assertEquals("", status.validationErrorCode)
        vc = loadSampleSdJwt("sdJwtAnimoMSISDN.txt")
        status = validator.validate(vc)
        assertEquals("", status.validationMessage)
        assertEquals("", status.validationErrorCode)

    }

    @Test
    fun `should fail on empty string`() {
        val status = validator.validate("")
        assertTrue(status.validationMessage.contains("empty", true))
        assertTrue(status.validationErrorCode.isNotEmpty())
    }

    @Test
    fun `should fail for invalid JWT format`() {
        val status = validator.validate("invalid.ajbsdj.sdjbja.jwt.structure~")
        assertTrue(status.validationMessage.contains("Invalid JWT format"))
    }

    @Test
    fun `should fail if vct is missing`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtAnimo.txt")) {
            it.remove("vct")
        }
        val status = validator.validate(vc)
        assertTrue(status.validationMessage.contains("vct"))
    }

    @Test
    fun `should fail for invalid typ header`() {
        val vc = loadSampleSdJwt("sdJwt.txt")
        val parts = vc.split("~")
        val jwtParts = parts[0].split(".")
        val headerJson = JSONObject(String(Base64.getUrlDecoder().decode(jwtParts[0])))
        headerJson.put("typ", "unsupported-type")
        val newHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.toString().toByteArray())
        val newJwt = listOf(newHeader, jwtParts[1], jwtParts[2]).joinToString(".")
        val modified = listOf(newJwt).plus(parts.drop(1)).joinToString("~")
        val status = validator.validate(modified)
        assertTrue(status.validationMessage.contains("typ"))
    }

    @Test
    fun `should fail for future iat`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtAnimo.txt")) {
            it.put("iat", 9999999999)
        }
        val status = validator.validate(vc)
        assertTrue(status.validationMessage.contains("iat", true))
    }

    @Test
    fun `should fail for future nbf`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtAnimo.txt")) {
            it.put("nbf", 9999999999)
        }
        val status = validator.validate(vc)
        assertTrue(status.validationMessage.contains("nbf", true))
    }

    @Test
    fun `should fail for expired exp`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtAnimo.txt")) {
            it.put("exp", 1234567890)
        }
        System.out.println("VC: " + vc)
        val status = validator.validate(vc)
        System.out.println("Validation message: " + status.validationMessage)
        assertTrue(status.validationMessage.contains("expired", true))
    }

    @Test
    fun `should fail for malformed disclosure`() {
        val base = loadSampleSdJwt("sdJwtAnimo.txt")
        val parts = base.split("~").toMutableList()

        parts[parts.lastIndex - 1] = "!!!not_base64"

        val modifiedVc = parts.joinToString("~")
        val status = validator.validate(modifiedVc)

        assertTrue(status.validationMessage.contains("Disclosure", ignoreCase = true))
    }

    @Test
    fun `should fail if number of disclosures does not match _sd array`() {
        val base = loadSampleSdJwt("sdJwtAnimo.txt")
        val parts = base.split("~").toMutableList()

        parts.add(parts.lastIndex, Base64.getUrlEncoder().withoutPadding()
            .encodeToString("[\"salt\",\"extra\",\"value\"]".toByteArray()))

        val modifiedVc = parts.joinToString("~")
        val status = validator.validate(modifiedVc)

        assertTrue(status.validationMessage.contains("Mismatch between number of disclosures", ignoreCase = true))
    }

    @Test
    fun `should fail if _sd digest is not correct length for sha-256`() {
        val base = loadSampleSdJwt("sdJwtAnimo.txt")
        val parts = base.split("~").toMutableList()

        val jwtParts = parts[0].split(".").toMutableList()
        val header = JSONObject(String(Base64.getUrlDecoder().decode(jwtParts[0])))
        val payload = JSONObject(String(Base64.getUrlDecoder().decode(jwtParts[1])))

        payload.remove("_sd_alg")

        val shortDigest = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(ByteArray(16)) // 16 bytes

        val sdArray = payload.getJSONArray("_sd")
        sdArray.put(0, shortDigest)

        val newPayload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payload.toString().toByteArray())

        val newJwt = jwtParts[0] + "." + newPayload + "." + jwtParts[2]
        parts[0] = newJwt

        val modifiedVc = parts.joinToString("~")

        val status = validator.validate(modifiedVc)
        println("Validation message: ${status.validationMessage}")

        assertTrue(
            status.validationMessage.contains("digest length", ignoreCase = true),
            "Expected failure due to invalid digest length"
        )
    }



    @Test
    fun `should not fail if optional parameter iss is missing`() {
        val base = loadSampleSdJwt("sdJwtAnimo.txt")
        val parts = base.split("~").toMutableList()

        val jwtParts = parts[0].split(".").toMutableList()
        val payloadJson = JSONObject(String(Base64.getUrlDecoder().decode(jwtParts[1])))
        payloadJson.remove("iss")

        val newPayload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.toString().toByteArray())

        parts[0] = jwtParts[0] + "." + newPayload + "." + jwtParts[2]
        val modifiedVc = parts.joinToString("~")
        println("Modified VC: $modifiedVc")
        val status = validator.validate(modifiedVc)

        assertTrue(status.validationMessage.isBlank())
    }




    @Test
    fun `should fail for disclosure with reserved claim name`() {
        val base = loadSampleSdJwt("sdJwtAnimo.txt")
        val parts = base.split("~").toMutableList()

        val badDisclosure = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("[\"salt\",\"_bad\",\"value\"]".toByteArray())

        parts[parts.lastIndex - 1] = badDisclosure

        val modifiedVc = parts.joinToString("~")
        val status = validator.validate(modifiedVc)

        println("Validation message: ${status.validationMessage}")
        assertTrue(status.validationMessage.contains("reserved", ignoreCase = true))
    }


    @Test
    fun `should fail for malformed KB JWT`() {
        val vc = loadSampleSdJwt("sdJwtAnimo.txt") + "header.payload"
        val status = validator.validate(vc)
        assertTrue(status.validationMessage.contains("Key Binding JWT"))
    }

    @Test
    fun `should fail for missing aud in KB JWT`() {
        val validKbJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6ImFiYyIsImNuZiI6eyJraWQiOiJrZXkifX0.c2lnbmF0dXJl"
        val vc = loadSampleSdJwt("sdJwtAnimo.txt") + validKbJwt
        val status = validator.validate(vc)
        assertTrue(status.validationMessage.contains("aud"))
    }
    @Test
    fun `should fail for tampered disclosure`() {
        val vc = getDisclosureTamperedSdJWT()
        val status = validator.validate(vc)
        assertTrue(status.validationMessage.contains("Disclosure SHA of claimName"))
    }
}