package io.mosip.vercred.vcverifier.credentialverifier.validator


import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_PROCESSING_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DISCLOSURE_CLAIM_NAME
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_JWT_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_KB_JWT_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_PROCESSING_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DISCLOSURE_CLAIM_NAME
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_JWT_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_KB_JWT_FORMAT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_MISSING_VCT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_VC_EXPIRED
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
        val vc = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        val parts = vc.split("~").toMutableList()
        val tamperedDisclosure = "WyIzeGN5R1RuS1lsYV9VOUtGVEtEVWtRIiwiZmFybWVySUQiLCIxMjM0NTY3ODkiXQ"
        parts[parts.lastIndex - 1] = tamperedDisclosure
        return parts.joinToString("~")
    }

    @Test
    fun `should validate a valid SD-JWT VC successfully`() {
        var vc = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        var status = validator.validate(vc)
        assertEquals("", status.validationMessage)
        assertEquals("", status.validationErrorCode)
        vc = loadSampleSdJwt("sdJwtWithRootLevelSd2.txt")
        status = validator.validate(vc)
        assertEquals("", status.validationMessage)
        assertEquals("", status.validationErrorCode)
        vc = loadSampleSdJwt("sdJwtWithRootLevelSd.txt")
        status = validator.validate(vc)
        assertEquals("", status.validationMessage)
        assertEquals("", status.validationErrorCode)

    }

    @Test
    fun `should fail on empty string`() {
        val status = validator.validate("")
        assertEquals("Validation Error: Input VC JSON string is null or empty.",status.validationMessage)
        assertEquals(CredentialValidatorConstants.ERROR_CODE_EMPTY_VC_JSON,status.validationErrorCode)
    }

    @Test
    fun `should fail for invalid JWT format`() {
        val status = validator.validate("invalid.ajbsdj.sdjbja.jwt.structure~")
        assertEquals(ERROR_MESSAGE_INVALID_JWT_FORMAT, status.validationMessage)
        assertEquals(ERROR_CODE_INVALID_JWT_FORMAT,status.validationErrorCode)
    }

    @Test
    fun `should fail if vct is missing`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.remove("vct")
        }
        val status = validator.validate(vc)
        assertEquals(ERROR_MESSAGE_MISSING_VCT, status.validationMessage)
        assertEquals(CredentialValidatorConstants.ERROR_CODE_MISSING_VCT,status.validationErrorCode)
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
        assertEquals("Unsupported or missing 'typ' in JWT header", status.validationMessage)
        assertEquals("${ERROR_CODE_INVALID}TYP",status.validationErrorCode)
    }

    @Test
    fun `should fail for future iat`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.put("iat", 9999999999)
        }
        val status = validator.validate(vc)
        assertEquals(ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE, status.validationMessage)
        assertEquals(ERROR_CODE_CURRENT_DATE_BEFORE_ISSUANCE_DATE,status.validationErrorCode)
    }

    @Test
    fun `should fail for future nbf`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.put("nbf", 9999999999)
        }
        val status = validator.validate(vc)
        assertEquals(ERROR_CURRENT_DATE_BEFORE_PROCESSING_DATE, status.validationMessage)
        assertEquals(ERROR_CODE_CURRENT_DATE_BEFORE_PROCESSING_DATE,status.validationErrorCode)
    }

    @Test
    fun `should fail for expired exp`() {
        val vc = modifySdJwtPayload(loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")) {
            it.put("exp", 1234567890)
        }
        val status = validator.validate(vc)
        assertEquals(ERROR_MESSAGE_VC_EXPIRED, status.validationMessage)
        assertEquals(ERROR_CODE_VC_EXPIRED,status.validationErrorCode)
    }

    @Test
    fun `should fail for malformed disclosure`() {
        val base = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        val parts = base.split("~").toMutableList()

        parts[parts.lastIndex - 1] = "!!!not_base64"

        val modifiedVc = parts.joinToString("~")
        val status = validator.validate(modifiedVc)
        assertEquals("Exception during Validation: Failed to parse disclosures.", status.validationMessage)
        assertEquals("${ERROR_CODE_INVALID}UNKNOWN",status.validationErrorCode)
    }

    @Test
    fun `should fail if _sd digest is not correct length for sha-256`() {
        val base = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        val parts = base.split("~").toMutableList()

        val jwtParts = parts[0].split(".").toMutableList()
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
        assertEquals("Invalid digest length at _sd[0]: expected 32 bytes, got 16", status.validationMessage)
        assertEquals("${ERROR_CODE_INVALID}DIGEST",status.validationErrorCode)

    }

    @Test
    fun `should not fail if optional parameter iss is missing`() {
        val base = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        val parts = base.split("~").toMutableList()

        val jwtParts = parts[0].split(".").toMutableList()
        val payloadJson = JSONObject(String(Base64.getUrlDecoder().decode(jwtParts[1])))
        payloadJson.remove("iss")

        val newPayload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(payloadJson.toString().toByteArray())

        parts[0] = jwtParts[0] + "." + newPayload + "." + jwtParts[2]
        val modifiedVc = parts.joinToString("~")
        val status = validator.validate(modifiedVc)

        assertEquals("", status.validationMessage)
        assertEquals("",status.validationErrorCode)
    }

    @Test
    fun `should fail for disclosure with reserved claim name`() {
        val base = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt")
        val parts = base.split("~").toMutableList()

        val badDisclosure = Base64.getUrlEncoder().withoutPadding()
            .encodeToString("[\"salt\",\"_bad\",\"value\"]".toByteArray())

        parts[parts.lastIndex - 1] = badDisclosure

        val modifiedVc = parts.joinToString("~")
        val status = validator.validate(modifiedVc)

        assertEquals("$ERROR_MESSAGE_INVALID_DISCLOSURE_CLAIM_NAME at index 12", status.validationMessage)
        assertEquals(ERROR_CODE_INVALID_DISCLOSURE_CLAIM_NAME,status.validationErrorCode)
    }

    @Test
    fun `should fail for malformed KB JWT`() {
        val vc = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt") + "header.payload"
        val status = validator.validate(vc)
        assertEquals(ERROR_MESSAGE_INVALID_KB_JWT_FORMAT, status.validationMessage)
        assertEquals(ERROR_CODE_INVALID_KB_JWT_FORMAT,status.validationErrorCode)
    }

    @Test
    fun `should fail for missing aud in KB JWT`() {
        val validKbJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6ImFiYyIsImNuZiI6eyJraWQiOiJrZXkifX0.c2lnbmF0dXJl"
        val vc = loadSampleSdJwt("sdJwtWithRootLevelSdNestedPayload.txt") + validKbJwt
        val status = validator.validate(vc)
        assertEquals("Missing 'aud' in Key Binding JWT", status.validationMessage)
        assertEquals("${ERROR_CODE_INVALID}AUD",status.validationErrorCode)
    }

    @Test
    fun `should fail for tampered disclosure`() {
        val vc = getDisclosureTamperedSdJWT()
        val status = validator.validate(vc)
        assertEquals("Digest value of all disclosures must be present in the '_sd' claim of payload", status.validationMessage)
        assertEquals("${ERROR_CODE_INVALID}DISCLOSURE",status.validationErrorCode)
    }

    @Test
    fun `should validate sd jwt with _sd in disclosures`() {
        val vc = loadSampleSdJwt("sdJwtWithClaimsInDisclosure.txt")
        val status = validator.validate(vc)
        assertEquals("", status.validationMessage)
        assertEquals("",status.validationErrorCode)
    }
}