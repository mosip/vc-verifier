package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.Constants.CONTEXT
import io.mosip.vercred.vcverifier.Constants.CREDENTIAL
import io.mosip.vercred.vcverifier.Constants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.Constants.ERROR_CONTEXT_FIRST_LINE
import io.mosip.vercred.vcverifier.Constants.ERROR_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.Constants.ERROR_EXPIRATION_DATE_INVALID
import io.mosip.vercred.vcverifier.Constants.ERROR_ISSUANCE_DATE_INVALID
import io.mosip.vercred.vcverifier.Constants.ERROR_MISSING_REQUIRED_FIELDS
import io.mosip.vercred.vcverifier.Constants.ERROR_TYPE_VERIFIABLE_CREDENTIAL
import io.mosip.vercred.vcverifier.Constants.ERROR_VALID_URI
import io.mosip.vercred.vcverifier.Constants.ERROR_VC_EXPIRED
import io.mosip.vercred.vcverifier.Constants.EXPIRATION_DATE
import io.mosip.vercred.vcverifier.Constants.ID
import io.mosip.vercred.vcverifier.Constants.ISSUANCE_DATE
import io.mosip.vercred.vcverifier.Constants.ISSUER
import io.mosip.vercred.vcverifier.Constants.PROOF
import io.mosip.vercred.vcverifier.Constants.TYPE
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

class CredentialsValidatorTest {


    private val credentialsValidator = CredentialsValidator()

    @Test
    fun `validate_empty_vc_json_string`(){
        val resultNull = credentialsValidator.validateCredential(null)
        assertEquals(false, resultNull.verificationStatus)
        assertEquals(ERROR_EMPTY_VC_JSON, resultNull.verificationErrorMessage)

        val resultEmpty = credentialsValidator.validateCredential(null)
        assertEquals(false, resultEmpty.verificationStatus)
        assertEquals(ERROR_EMPTY_VC_JSON, resultEmpty.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.remove(CREDENTIAL)

        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CREDENTIAL", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_id`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(CREDENTIAL).remove(ID)

        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CREDENTIAL.$ID", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_issuer`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(CREDENTIAL).remove(ISSUER)

        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CREDENTIAL.$ISSUER", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_type`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(CREDENTIAL).remove(TYPE)

        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CREDENTIAL.$TYPE", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_proof`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(CREDENTIAL).remove(PROOF)

        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CREDENTIAL.$PROOF", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_context`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(CREDENTIAL).remove(CONTEXT)

        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CREDENTIAL.$CONTEXT", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_issuanceDate`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(CREDENTIAL).remove(ISSUANCE_DATE)

        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CREDENTIAL.$ISSUANCE_DATE", result.verificationErrorMessage)
    }

    @Test
    fun `validate_mandatory_fields_missing_credential_credentialSubject`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(CREDENTIAL).remove(CREDENTIAL_SUBJECT)

        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CREDENTIAL.$CREDENTIAL_SUBJECT", result.verificationErrorMessage)
    }

    @Test
    fun `invalid_credential_context`(){

        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(CREDENTIAL).getJSONArray(CONTEXT).put(0, "http://www/google.com")

        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_CONTEXT_FIRST_LINE", result.verificationErrorMessage)
    }




    @Test
    fun `invalid_credential_issuer_id`(){
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(CREDENTIAL).put(ISSUER, "invalid-uri")

        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$CREDENTIAL.$ISSUER$ERROR_VALID_URI", result.verificationErrorMessage)
    }

    @Test
    fun `invalid_credential_issuance_date`(){
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(CREDENTIAL).put(ISSUANCE_DATE, "2024-15-02T17:36:13.644Z")

        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_ISSUANCE_DATE_INVALID", result.verificationErrorMessage)
    }

    @Test
    fun `invalid_credential_expiration_date`(){
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(CREDENTIAL).put(EXPIRATION_DATE, "2034-15-02T17:36:13.644Z")

        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals("$ERROR_EXPIRATION_DATE_INVALID", result.verificationErrorMessage)
    }

    @Test
    fun `invalid_credential_type`() {
        val sampleVcObject = JSONObject(sampleVc)
        val credentialObject = sampleVcObject.getJSONObject(CREDENTIAL)
        credentialObject.getJSONArray(TYPE).put(0, "SampleVC")
        credentialObject.getJSONArray(TYPE).put(1, "UnknownCredentialType")
        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(false, result.verificationStatus)
        assertEquals(ERROR_TYPE_VERIFIABLE_CREDENTIAL, result.verificationErrorMessage)
    }

    @Test
    fun `test_VC_expired`(){
        val sampleVcObject = JSONObject(sampleVc)
        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(true,result.verificationStatus)
        assertEquals(ERROR_VC_EXPIRED,result.verificationErrorMessage)
    }

    @Test
    fun `test_VC_not_expired`(){
        val sampleVcObject = JSONObject(sampleVc)
        sampleVcObject.getJSONObject(CREDENTIAL).put(EXPIRATION_DATE, "2034-12-02T17:36:13.644Z")
        val result = credentialsValidator.validateCredential(sampleVcObject.toString())
        assertEquals(true,result.verificationStatus)
        assertEquals("",result.verificationErrorMessage)
    }



    companion object{

        val sampleVc = """
            {
            "credential": {
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
                "expirationDate": "2014-09-02T17:36:13.644Z",
                "issuer": "https://apn/ida-controller.json",
                "proof": {
                    "created": "2024-09-02T17:36:13Z",
                    "jws": "eyJiNj",
                    "proofPurpose": "assertionMethod",
                    "type": "RsaSignature2018",
                    "verificationMethod": "https://apy.json"
                },
                "type": [
                    "VerifiableCredential",
                    "MOSIPVerifiableCredential"
                ]
            }
        }
        
        
        """.trimIndent()
    }
}