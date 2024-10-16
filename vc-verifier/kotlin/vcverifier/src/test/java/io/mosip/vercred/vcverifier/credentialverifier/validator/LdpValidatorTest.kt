package io.mosip.vercred.vcverifier.credentialverifier.validator

import io.mockk.every
import io.mockk.mockkStatic
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CONTEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SCHEMA
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_STATUS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_ALGORITHM_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CONTEXT_FIRST_LINE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_AFTER_VALID_UNTIL
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_EXPIRATION_DATE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_FIELD
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_ISSUANCE_DATE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MISSING_REQUIRED_FIELDS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_PROOF_TYPE_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_TYPE_VERIFIABLE_CREDENTIAL
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EVIDENCE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXCEPTION_DURING_VALIDATION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXPIRATION_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUER
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.JWS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.REFRESH_SERVICE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TERMS_OF_USE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TYPE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_UNTIL
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class LdpValidatorTest {

    private val credentialsValidator = LdpValidator()

    @Test
    fun `validateCredential should return error when JSON parsing fails`() {
        mockkStatic(JSONObject::class)
        val invalidJsonString = """
            {"test": "test"}
        """.trimIndent()

        every { JSONObject(invalidJsonString) } throws Exception("JSON parsing error")

        val result = credentialsValidator.validate(invalidJsonString)
        assertFalse(result.verificationStatus)
        assertEquals("${EXCEPTION_DURING_VALIDATION}JSON parsing error", result.verificationErrorMessage)
    }

    @Test
    fun `validate empty vc json string`(){

        val resultEmpty = credentialsValidator.validate("")
        assertEquals(false, resultEmpty.verificationStatus)
        assertEquals(ERROR_EMPTY_VC_JSON, resultEmpty.verificationErrorMessage)
    }

    @Test
    fun `validate mandatory fields missing credential issuer`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.remove(ISSUER)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$ISSUER", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_type`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.remove(TYPE)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$TYPE", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_proof`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.remove(PROOF)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$PROOF", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_context`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.remove(CONTEXT)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CONTEXT", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_issuanceDate`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.remove(ISSUANCE_DATE)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$ISSUANCE_DATE", result.verificationErrorMessage)
    }

    @Test
    fun `validate_passed_issuanceDate`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.put(ISSUANCE_DATE, "2024-09-02T17:36:13.644Z")

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }

    @Test
    fun `validate_not_passed_issuanceDate`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.put(ISSUANCE_DATE, "2026-09-02T17:36:13.644Z")

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_credentialSubject`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.remove(CREDENTIAL_SUBJECT)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CREDENTIAL_SUBJECT", result.verificationErrorMessage)
    }

    @Test
    fun `invalid_credential_context`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONArray(CONTEXT).put(0, "http://www/google.com")

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_CONTEXT_FIRST_LINE", result.verificationErrorMessage)
    }

    @Test
    fun `invalid_credential_issuer_id`(){
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.put(ISSUER, "invalid-uri")

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_INVALID_URI$ISSUER", result.verificationErrorMessage)
    }

    @Test
    fun `invalid_credential_issuance_date`(){
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.put(ISSUANCE_DATE, "2024-15-02T17:36:13.644Z")

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_ISSUANCE_DATE_INVALID", result.verificationErrorMessage)
    }

    @Test
    fun `invalid_credential_expiration_date`(){
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.put(EXPIRATION_DATE, "2034-15-02T17:36:13.644Z")

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_EXPIRATION_DATE_INVALID", result.verificationErrorMessage)
    }

    @Test
    fun `invalid_credential_type`() {
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONArray(TYPE).put(0, "SampleVC")
        sampleVcObject.getJSONArray(TYPE).put(1, "UnknownCredentialType")
        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals(ERROR_TYPE_VERIFIABLE_CREDENTIAL, result.verificationErrorMessage)
    }

    @Test
    fun `test_VC_expired`(){
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.put(EXPIRATION_DATE, "2014-12-02T17:36:13.644Z")
        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true,result.verificationStatus)
        assertEquals(ERROR_VC_EXPIRED,result.verificationErrorMessage)
    }

    @Test
    fun `test_VC_not_expired`(){
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.put(EXPIRATION_DATE, "2034-12-02T17:36:13.644Z")
        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true,result.verificationStatus)
        assertEquals("",result.verificationErrorMessage)
    }

    @Test
    fun `test_VC_without_expiration`(){
        val sampleVcObject = JSONObject(sampleVc)
        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals("",result.verificationErrorMessage)
        assertEquals(true,result.verificationStatus)

    }

    @Test
    fun `test without jws`() {
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.remove(JWS)
        val result = credentialsValidator.validate(sampleVc)
        assertEquals(true, result.verificationStatus)
    }


    @Test
    fun `test invalid algorithm in jws`() {
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(PROOF).put(JWS, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(ERROR_ALGORITHM_NOT_SUPPORTED, result.verificationErrorMessage)
        assertEquals(false, result.verificationStatus)

    }

    @Test
    fun `test valid algorithm in jws`() {
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.put(JWS, "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJraWQiOiJLYlJXRU9YQ0pVRENWVnVET2ZsSkRQWnAtXzNqMEZvajd1RVZHd19xOEdzIiwiYWxnIjoiUFMyNTYifQ..NEcXf5IuDf0eJcBbtIBsXC2bZeOzNBduWG7Vz9A3ePcvh-SuwggPcCPQLrdgl79ta5bYsKsJSKVSS0Xg-GvlY71I2OzU778Bkq52LIDtSXY3DrxQEvM-BqjKLBB-ScA850pG2gV-k_8nkCPmAdvda_jj2Vlkss7VPB5LI6skWTgM4MOyvlMzZCzqmifqTzHLVgefzfixld7E38X7wxzEZfn2lY_fRfWqcL8pKL_kijTHwdTWLb9hMQtP9vlk2iarbT8TmZqutZD8etd1PBFm7V_izcY9cO75A4N3fVrr6NC50cDHDshPZFS48uTBDK-SSePxibpmq1afaS_VX6kX7A")
        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
    }

    @Test
    fun `test without proof type`() {
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(PROOF).remove(TYPE)
        val result = credentialsValidator.validate(sampleVcObject.toString())

        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$PROOF.$TYPE", result.verificationErrorMessage)
        assertEquals(false, result.verificationStatus)
    }


    @Test
    fun `test invalid proof type`() {
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(PROOF).put(TYPE, "ASASignature2018")
        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(ERROR_PROOF_TYPE_NOT_SUPPORTED, result.verificationErrorMessage)
        assertEquals(false, result.verificationStatus)

    }

    @Test
    fun `test valid proof type`() {
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(PROOF).put(TYPE, "RsaSignature2018")
        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_context_v2`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.remove(CONTEXT)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CONTEXT", result.verificationErrorMessage)
    }

    @Test
    fun `validate_unsupported_context_version`(){
        val sampleVcObject = JSONObject(sampleVcV2)
        sampleVcObject.put(CONTEXT, arrayOf("http://www.google.com/"))

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_CONTEXT_FIRST_LINE", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_issuer_v2`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.remove(ISSUER)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$ISSUER", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_type_v2`(){

        val sampleVcObject = JSONObject(sampleVcV2)
        sampleVcObject.remove(TYPE)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$TYPE", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_credentialSubject_v2`(){

        val sampleVcObject = JSONObject(sampleVcV2)
        sampleVcObject.remove(CREDENTIAL_SUBJECT)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CREDENTIAL_SUBJECT", result.verificationErrorMessage)
    }


    @Test
    fun `test_without_ValidFrom_v2`(){

        val sampleVcObject = JSONObject(sampleVcV2)
        sampleVcObject.remove(VALID_FROM)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals("", result.verificationErrorMessage)
        assertEquals(true, result.verificationStatus)

    }

    @Test
    fun `test_without_CurrentDate_before_validFrom`(){

        val sampleVcObject = JSONObject(sampleVcV2)
        sampleVcObject.put(VALID_FROM, "2026-12-02T17:36:13.644Z")

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(ERROR_CURRENT_DATE_BEFORE_VALID_FROM, result.verificationErrorMessage)
        assertEquals(false, result.verificationStatus)

    }

    @Test
    fun `test_without_ValidUntil_v2`(){

        val sampleVcObject = JSONObject(sampleVcV2)
        sampleVcObject.remove(VALID_UNTIL)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }

    @Test
    fun `test_without_CurrentDate_after_validUntil`(){

        val sampleVcObject = JSONObject(sampleVcV2)
        sampleVcObject.put(VALID_UNTIL, "2023-12-02T17:36:13.644Z")

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals(ERROR_CURRENT_DATE_AFTER_VALID_UNTIL, result.verificationErrorMessage)


    }

    @Test
    fun `test_without_both_date_v2`(){

        val sampleVcObject = JSONObject(sampleVcV2)
        sampleVcObject.remove(VALID_UNTIL)
        sampleVcObject.remove(VALID_FROM)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }

    @Test
    fun test_credentialStatus_object_valid_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val credentialStatusObject = JSONObject()
        credentialStatusObject.put(ID, "https://google.com/")
        credentialStatusObject.put(TYPE, "Type")
        sampleVcObject.put(CREDENTIAL_STATUS, credentialStatusObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }

    @Test
    fun test_credentialStatus_object_invalid_v1(){
        val sampleVcObject = JSONObject(sampleVc)

        sampleVcObject.put(CREDENTIAL_STATUS, "Invalid String Type")

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_INVALID_FIELD$CREDENTIAL_STATUS", result.verificationErrorMessage)
    }

    @Test
    fun test_credentialStatus_object_without_id_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val credentialStatusObject = JSONObject()
        credentialStatusObject.put(TYPE, "Type")
        sampleVcObject.put(CREDENTIAL_STATUS, credentialStatusObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$ID", result.verificationErrorMessage)
    }

    @Test
    fun test_credentialStatus_object_without_type_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val credentialStatusObject = JSONObject()
        credentialStatusObject.put(ID, "https://google.com/")
        sampleVcObject.put(CREDENTIAL_STATUS, credentialStatusObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$TYPE", result.verificationErrorMessage)
    }

    @Test
    fun test_credentialStatus_array_valid_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val credentialStatusObject = JSONObject()
        credentialStatusObject.put(ID, "https://google.com/")
        credentialStatusObject.put(TYPE, "Type")
        sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())

        sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(0, credentialStatusObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }


    @Test
    fun test_credentialStatus_array_without_id_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val credentialStatusObject = JSONObject()
        credentialStatusObject.put(TYPE, "Type")
        sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())

        sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(0, credentialStatusObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$ID", result.verificationErrorMessage)
    }

    @Test
    fun test_credentialStatus_array_without_type_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val credentialStatusObject = JSONObject()
        credentialStatusObject.put(ID, "https://google.com/")
        sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())

        sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(0, credentialStatusObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$TYPE", result.verificationErrorMessage)
    }

    @Test
    fun test_credentialStatus_object_without_id_v2(){
        val sampleVcObject = JSONObject(sampleVcV2)
        val credentialStatusObject = JSONObject()
        credentialStatusObject.put(TYPE, "Type")
        sampleVcObject.put(CREDENTIAL_STATUS, credentialStatusObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }

    @Test
    fun test_credentialStatus_object_without_type_v2(){
        val sampleVcObject = JSONObject(sampleVcV2)
        val credentialStatusObject = JSONObject()
        credentialStatusObject.put(ID, "https://google.com/")
        sampleVcObject.put(CREDENTIAL_STATUS, credentialStatusObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$TYPE", result.verificationErrorMessage)
    }

    @Test
    fun test_credentialStatus_array_without_id_v2(){
        val sampleVcObject = JSONObject(sampleVc)
        val credentialStatusObject = JSONObject()
        credentialStatusObject.put(TYPE, "Type")
        sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())

        sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(0, credentialStatusObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$ID", result.verificationErrorMessage)
    }

    @Test
    fun test_credentialStatus_array_without_type_v2(){
        val sampleVcObject = JSONObject(sampleVc)
        val credentialStatusObject = JSONObject()
        credentialStatusObject.put(ID, "https://google.com/")
        sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())

        sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(0, credentialStatusObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$TYPE", result.verificationErrorMessage)
    }




    @Test
    fun test_evidence_object_valid_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(EVIDENCE, JSONArray())
        sampleVcObject.getJSONArray(EVIDENCE).put(0, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }

    @Test
    fun test_evidence_object_invalid_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.put(EVIDENCE, "Invalid String Type")

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_INVALID_FIELD$EVIDENCE", result.verificationErrorMessage)
    }

    @Test
    fun test_evidence_object_without_id_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val evidenceObject = JSONObject()
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(EVIDENCE, JSONArray())
        sampleVcObject.getJSONArray(EVIDENCE).put(0, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }

    @Test
    fun test_evidence_object_without_type_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        sampleVcObject.put(EVIDENCE, JSONArray())
        sampleVcObject.getJSONArray(EVIDENCE).put(0, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$EVIDENCE.$TYPE", result.verificationErrorMessage)
    }

    @Test
    fun test_evidence_object_without_id_v2(){
        val sampleVcObject = JSONObject(sampleVcV2)
        val evidenceObject = JSONObject()
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(EVIDENCE, JSONArray())
        sampleVcObject.getJSONArray(EVIDENCE).put(0, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }


    @Test
    fun test_evidence_object_without_type_v2(){
        val sampleVcObject = JSONObject(sampleVc)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        sampleVcObject.put(EVIDENCE, JSONArray())
        sampleVcObject.getJSONArray(EVIDENCE).put(0, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$EVIDENCE.$TYPE", result.verificationErrorMessage)
    }

    @Test
    fun test_credential_schema_object_invalid_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.put(CREDENTIAL_SCHEMA, "Invalid String Type")

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_INVALID_FIELD$CREDENTIAL_SCHEMA", result.verificationErrorMessage)
    }

    @Test
    fun test_credential_schema_object_valid_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(CREDENTIAL_SCHEMA, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }

    @Test
    fun test_credential_schema_object_missing_id_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val evidenceObject = JSONObject()
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(CREDENTIAL_SCHEMA, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_SCHEMA.$ID", result.verificationErrorMessage)
    }

    @Test
    fun test_credential_schema_object_missing_type_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        sampleVcObject.put(CREDENTIAL_SCHEMA, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_SCHEMA.$TYPE", result.verificationErrorMessage)
    }

    @Test
    fun test_credential_schema_array_valid_v2(){
        val sampleVcObject = JSONObject(sampleVcV2)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(CREDENTIAL_SCHEMA, JSONArray())
        sampleVcObject.getJSONArray(CREDENTIAL_SCHEMA).put(0, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }

    @Test
    fun test_credential_schema_array_missing_id_v2(){
        val sampleVcObject = JSONObject(sampleVcV2)
        val evidenceObject = JSONObject()
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(CREDENTIAL_SCHEMA, JSONArray())
        sampleVcObject.getJSONArray(CREDENTIAL_SCHEMA).put(0, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_SCHEMA.$ID", result.verificationErrorMessage)
    }

    @Test
    fun test_credential_schema_array_missing_type_v2(){
        val sampleVcObject = JSONObject(sampleVcV2)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        sampleVcObject.put(CREDENTIAL_SCHEMA, JSONArray())
        sampleVcObject.getJSONArray(CREDENTIAL_SCHEMA).put(0, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_SCHEMA.$TYPE", result.verificationErrorMessage)
    }


    @Test
    fun test_refresh_service_object_invalid(){
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.put(REFRESH_SERVICE, "Invalid String Type")

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_INVALID_FIELD$REFRESH_SERVICE", result.verificationErrorMessage)
    }

    @Test
    fun test_refresh_service_object_valid_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(REFRESH_SERVICE, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }

    @Test
    fun test_refresh_service_object_missing_id_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val evidenceObject = JSONObject()
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(REFRESH_SERVICE, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$REFRESH_SERVICE.$ID", result.verificationErrorMessage)
    }

    @Test
    fun test_refresh_service_object_missing_type_v1(){
        val sampleVcObject = JSONObject(sampleVc)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        sampleVcObject.put(REFRESH_SERVICE, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$REFRESH_SERVICE.$TYPE", result.verificationErrorMessage)
    }

    @Test
    fun test_refresh_service_object_valid_v2(){
        val sampleVcObject = JSONObject(sampleVcV2)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(REFRESH_SERVICE, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }

    @Test
    fun test_refresh_service_object_missing_id_v2(){
        val sampleVcObject = JSONObject(sampleVcV2)
        val evidenceObject = JSONObject()
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(REFRESH_SERVICE, evidenceObject)


        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals("", result.verificationErrorMessage)
        assertEquals(true, result.verificationStatus)

    }

    @Test
    fun test_refresh_service_object_missing_type_v2(){
        val sampleVcObject = JSONObject(sampleVcV2)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        sampleVcObject.put(REFRESH_SERVICE, evidenceObject)


        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$REFRESH_SERVICE.$TYPE", result.verificationErrorMessage)

    }

    @Test
    fun test_terms_of_use_object_valid(){
        val sampleVcObject = JSONObject(sampleVcV2)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(TERMS_OF_USE, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(true, result.verificationStatus)
        assertEquals("", result.verificationErrorMessage)
    }

    @Test
    fun test_terms_of_use_object_missing_id(){
        val sampleVcObject = JSONObject(sampleVcV2)
        val evidenceObject = JSONObject()
        evidenceObject.put(TYPE, "Type")
        sampleVcObject.put(TERMS_OF_USE, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals("", result.verificationErrorMessage)
        assertEquals(true, result.verificationStatus)

    }

    @Test
    fun test_terms_of_use_object_missing_type(){
        val sampleVcObject = JSONObject(sampleVcV2)
        val evidenceObject = JSONObject()
        evidenceObject.put(ID, "https://google.com/")
        sampleVcObject.put(TERMS_OF_USE, evidenceObject)

        val result = credentialsValidator.validate(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$TERMS_OF_USE.$TYPE", result.verificationErrorMessage)

    }

    companion object{

        val sampleVc = """
        {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://apisip-ida-context.json",
                    {
                        "sec": "https://w3id.org/security#"
                    }
                ],
                "credentialSubject": {
                    "VID": "65327817407",
                    "face": "data:image/jpeg;base64,/9",
                    "gender": [
                        {
                            "language": "eng",
                            "value": "MLE"
                        }
                    ],
                    "phone": "+++7765837077",
                    "city": [
                        {
                            "language": "eng",
                            "value": "TEST_CITYeng"
                        }
                    ],
                    "fullName": [
                        {
                            "language": "eng",
                            "value": "TEST_FULLNAMEeng"
                        }
                    ],
                    "addressLine1": [
                        {
                            "language": "eng",
                            "value": "TEST_ADDRESSLINE1eng"
                        }
                    ],
                    "dateOfBirth": "1992/04/15",
                    "id": "invalid-uri",
                    "email": "mosipuser123@mailinator.com"
                },
                "id": "https://ida.test.net/credentials/b5d20f0a-a9b8-486a-9d60",
                "issuanceDate": "2024-09-02T17:36:13.644Z",
                "issuer": "https://apn/ida-controller.json",
                "proof": {
                    "created": "2024-09-02T17:36:13Z",
                    "jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJraWQiOiJLYlJXRU9YQ0pVRENWVnVET2ZsSkRQWnAtXzNqMEZvajd1RVZHd19xOEdzIiwiYWxnIjoiUFMyNTYifQ..NEcXf5IuDf0eJcBbtIBsXC2bZeOzNBduWG7Vz9A3ePcvh-SuwggPcCPQLrdgl79ta5bYsKsJSKVSS0Xg-GvlY71I2OzU778Bkq52LIDtSXY3DrxQEvM-BqjKLBB-ScA850pG2gV-k_8nkCPmAdvda_jj2Vlkss7VPB5LI6skWTgM4MOyvlMzZCzqmifqTzHLVgefzfixld7E38X7wxzEZfn2lY_fRfWqcL8pKL_kijTHwdTWLb9hMQtP9vlk2iarbT8TmZqutZD8etd1PBFm7V_izcY9cO75A4N3fVrr6NC50cDHDshPZFS48uTBDK-SSePxibpmq1afaS_VX6kX7A",
                    "proofPurpose": "assertionMethod",
                    "type": "RsaSignature2018",
                    "verificationMethod": "https://apy.json"
                },
                "type": [
                    "VerifiableCredential",
                    "MOSIPVerifiableCredential"
                ]
            }
        
        
        """.trimIndent()
    }

    val sampleVcV2 = """
        {
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://apisip-ida-context.json",
                    {
                        "sec": "https://w3id.org/security#"
                    }
                ],
                "credentialSubject": {
                    "VID": "65327817407",
                    "face": "data:image/jpeg;base64,/9",
                    "gender": [
                        {
                            "language": "eng",
                            "value": "MLE"
                        }
                    ],
                    "phone": "+++7765837077",
                    "city": [
                        {
                            "language": "eng",
                            "value": "TEST_CITYeng"
                        }
                    ],
                    "fullName": [
                        {
                            "language": "eng",
                            "value": "TEST_FULLNAMEeng"
                        }
                    ],
                    "addressLine1": [
                        {
                            "language": "eng",
                            "value": "TEST_ADDRESSLINE1eng"
                        }
                    ],
                    "dateOfBirth": "1992/04/15",
                    "id": "invalid-uri",
                    "email": "mosipuser123@mailinator.com"
                },
                "id": "https://ida.test.net/credentials/b5d20f0a-a9b8-486a-9d60",
                "issuer": "https://apn/ida-controller.json",
                "validFrom": "2024-09-02T17:36:13.644Z",
                "proof": {
                    "created": "2024-09-02T17:36:13Z",
                    "jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJraWQiOiJLYlJXRU9YQ0pVRENWVnVET2ZsSkRQWnAtXzNqMEZvajd1RVZHd19xOEdzIiwiYWxnIjoiUFMyNTYifQ..NEcXf5IuDf0eJcBbtIBsXC2bZeOzNBduWG7Vz9A3ePcvh-SuwggPcCPQLrdgl79ta5bYsKsJSKVSS0Xg-GvlY71I2OzU778Bkq52LIDtSXY3DrxQEvM-BqjKLBB-ScA850pG2gV-k_8nkCPmAdvda_jj2Vlkss7VPB5LI6skWTgM4MOyvlMzZCzqmifqTzHLVgefzfixld7E38X7wxzEZfn2lY_fRfWqcL8pKL_kijTHwdTWLb9hMQtP9vlk2iarbT8TmZqutZD8etd1PBFm7V_izcY9cO75A4N3fVrr6NC50cDHDshPZFS48uTBDK-SSePxibpmq1afaS_VX6kX7A",
                    "proofPurpose": "assertionMethod",
                    "type": "RsaSignature2018",
                    "verificationMethod": "https://apy.json"
                },
                "type": [
                    "VerifiableCredential",
                    "MOSIPVerifiableCredential"
                ]
            }
        
        
        """.trimIndent()
}
