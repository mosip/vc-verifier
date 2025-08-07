package io.mosip.vercred.vcverifier.credentialverifier.validator

import android.os.Build
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ALGORITHM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CONTEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SCHEMA
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_STATUS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CREDENTIAL_SUBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.DESCRIPTION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_CURRENT_DATE_BEFORE_VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_GENERIC
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_ALGORITHM_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_CONTEXT_FIRST_LINE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CREDENTIAL_SUBJECT_NON_NULL_OBJECT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CURRENT_DATE_BEFORE_VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_DESCRIPTION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_EMPTY_VC_JSON
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_EXPIRATION_DATE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_FIELD
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_ISSUANCE_DATE_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MISSING_REQUIRED_FIELDS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_PROOF_TYPE_NOT_SUPPORTED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_TYPE_VERIFIABLE_CREDENTIAL
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_INVALID_URI
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_NAME
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_VC_EXPIRED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_VALID_FROM_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_VALID_UNTIL_INVALID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EVIDENCE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXCEPTION_DURING_VALIDATION
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.EXPIRATION_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ID
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUANCE_DATE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ISSUER
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.JWS
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.LANGUAGE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.NAME
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.PROOF
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.REFRESH_SERVICE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TERMS_OF_USE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.TYPE
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_FROM
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALID_UNTIL
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.VALUE
import io.mosip.vercred.vcverifier.utils.BuildConfig
import io.mosip.vercred.vcverifier.utils.DateUtils
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test

class LdpValidatorTest {
    @BeforeEach
    fun setUp() {
        mockkObject(BuildConfig)
        mockkObject(DateUtils)
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O
    }

    @AfterEach
    fun after() {
        clearAllMocks()
    }

    private val credentialsValidator: LdpValidator = LdpValidator()

    @Nested
    inner class NameValidationTest {
        @Test
        fun `test when name is of type string and valid`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.put(NAME, "test name")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when name is of type object and valid`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val nameArray = JSONArray()
            val nameObject = JSONObject()
            nameObject.put(LANGUAGE, "en")
            nameObject.put(VALUE, "test name")
            nameArray.put(0, nameObject)
            sampleVcObject.put(NAME, nameArray)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when name is of type object and invalid`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val nameArray = JSONArray()
            val nameObject = JSONObject()
            nameObject.put(VALUE, "test name")
            nameArray.put(0, nameObject)
            sampleVcObject.put(NAME, nameArray)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals(ERROR_MESSAGE_NAME, result.validationMessage)
            assertEquals("${ERROR_CODE_INVALID}${NAME.uppercase()}", result.validationErrorCode)
        }

    }

    @Nested
    inner class DescriptionValidationTests{
        @Test
        fun `test when description is of type string and valid`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.put(DESCRIPTION, "test name")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when description is of type object and valid`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val nameArray = JSONArray()
            val nameObject = JSONObject()
            nameObject.put(LANGUAGE, "en")
            nameObject.put(VALUE, "test desc")
            nameArray.put(0, nameObject)
            sampleVcObject.put(DESCRIPTION, nameArray)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when description is of type string and invalid`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val nameArray = JSONArray()
            val nameObject = JSONObject()
            nameObject.put(VALUE, "test desc")
            nameArray.put(0, nameObject)
            sampleVcObject.put(DESCRIPTION, nameArray)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals(ERROR_MESSAGE_DESCRIPTION, result.validationMessage)
            assertEquals("${ERROR_CODE_INVALID}${DESCRIPTION.uppercase()}", result.validationErrorCode)
        }
    }

    @Nested
    inner class CredentialSubjectTests{
        @Test
        fun `test when credentialSubject is missing`(){

            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.remove(CREDENTIAL_SUBJECT)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CREDENTIAL_SUBJECT", result.validationMessage)
            assertEquals("${ERROR_CODE_MISSING}${CREDENTIAL_SUBJECT.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialSubject_id is missing`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credSubjectObject = sampleVcObject.get(CREDENTIAL_SUBJECT)
            (credSubjectObject as JSONObject).remove(ID)
            sampleVcObject.put(CREDENTIAL_SUBJECT, credSubjectObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
            
        }

        @Test
        fun `test when credentialSubject is of type string and empty`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)

            sampleVcObject.put(CREDENTIAL_SUBJECT, "")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            assertEquals(ERROR_CREDENTIAL_SUBJECT_NON_NULL_OBJECT, result.validationMessage)
            assertEquals("${ERROR_CODE_INVALID}${CREDENTIAL_SUBJECT.uppercase()}", result.validationErrorCode)
            
        }

        @Test
        fun `test when credentialSubject is missing for v2`(){

            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.remove(CREDENTIAL_SUBJECT)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CREDENTIAL_SUBJECT", result.validationMessage)
            assertEquals("${ERROR_CODE_MISSING}${CREDENTIAL_SUBJECT.uppercase()}", result.validationErrorCode)
        }
    }

    @Nested
    inner class CredentialStatusTests{

        @Test
        fun `test when credentialStatus object is valid for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(ID, "https://google.com/")
            credentialStatusObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_STATUS, credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when credentialStatus object is of invalid type 'string' for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)

            sampleVcObject.put(CREDENTIAL_STATUS, "Invalid String Type")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_INVALID_FIELD$CREDENTIAL_STATUS", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${CREDENTIAL_STATUS.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialStatus_id is missing for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_STATUS, credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$ID", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${CREDENTIAL_STATUS.uppercase()}_${ID.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialStatus_type is missing for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(ID, "https://google.com/")
            sampleVcObject.put(CREDENTIAL_STATUS, credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$TYPE", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${CREDENTIAL_STATUS.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialStatus object has empty id for v1`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(ID, "")
            credentialStatusObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_STATUS, credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("$CREDENTIAL_STATUS.$ID cannot be null or empty.", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${CREDENTIAL_STATUS.uppercase()}_${ID.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialStatus object has empty type for v1`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(ID, "https://google.com/")
            credentialStatusObject.put(TYPE, "")
            sampleVcObject.put(CREDENTIAL_STATUS, credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("$CREDENTIAL_STATUS.$TYPE cannot be null or empty.", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${CREDENTIAL_STATUS.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }


        @Test
        fun `test when credentialStatus is of type 'array' and valid for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(ID, "https://google.com/")
            credentialStatusObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())

            sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(0, credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when credentialStatus is of type 'array' and 'id' is missing for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())

            sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(0, credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$ID", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${CREDENTIAL_STATUS.uppercase()}_${ID.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialStatus array has object with empty id for v1`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(ID, "")
            credentialStatusObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())
            sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("$CREDENTIAL_STATUS.$ID cannot be null or empty.", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${CREDENTIAL_STATUS.uppercase()}_${ID.uppercase()}", result.validationErrorCode)
        }


        @Test
        fun `test when credentialStatus is of type 'array' and type is missing for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(ID, "https://google.com/")
            sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())

            sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(0, credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$TYPE", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${CREDENTIAL_STATUS.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialStatus array has object with empty type for v1`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(ID, "https://google.com/")
            credentialStatusObject.put(TYPE, "")
            sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())
            sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("$CREDENTIAL_STATUS.$TYPE cannot be null or empty.", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${CREDENTIAL_STATUS.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialStatus is of type 'object' and 'id' is missing for v2`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_STATUS, credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when credentialStatus is of type 'object' and 'type' is missing for v2`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(ID, "https://google.com/")
            sampleVcObject.put(CREDENTIAL_STATUS, credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$TYPE", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${CREDENTIAL_STATUS.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialStatus array has object with empty type for v2`() {
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(ID, "https://google.com/")
            credentialStatusObject.put(TYPE, "")

            sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())
            sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("$CREDENTIAL_STATUS.$TYPE cannot be null or empty.", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${CREDENTIAL_STATUS.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }


        @Test
        fun `test when credentialStatus is of type 'array' and 'id' is missing for v2`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())
            sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(0, credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$ID", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${CREDENTIAL_STATUS.uppercase()}_${ID.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialStatus is of type 'array' and 'type' is missing for v2`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val credentialStatusObject = JSONObject()
            credentialStatusObject.put(ID, "https://google.com/")
            sampleVcObject.put(CREDENTIAL_STATUS, JSONArray())
            sampleVcObject.getJSONArray(CREDENTIAL_STATUS).put(0, credentialStatusObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_STATUS.$TYPE", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${CREDENTIAL_STATUS.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }

    }

    @Nested
    inner class EvidenceTests{
        @Test
        fun `test when evidence is of type 'object' and valid for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(EVIDENCE, JSONArray())
            sampleVcObject.getJSONArray(EVIDENCE).put(0, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when evidence is of type 'object' and invalid for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.put(EVIDENCE, "Invalid String Type")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_INVALID_FIELD$EVIDENCE", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${EVIDENCE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when evidence is of type 'object' and without 'id' for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val evidenceObject = JSONObject()
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(EVIDENCE, JSONArray())
            sampleVcObject.getJSONArray(EVIDENCE).put(0, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when evidence is of type 'object' and without 'type' for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            sampleVcObject.put(EVIDENCE, JSONArray())
            sampleVcObject.getJSONArray(EVIDENCE).put(0, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$EVIDENCE.$TYPE", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${EVIDENCE.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)

        }

        @Test
        fun `test when evidence is of type 'object' and without 'id' for v2`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val evidenceObject = JSONObject()
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(EVIDENCE, JSONArray())
            sampleVcObject.getJSONArray(EVIDENCE).put(0, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }


        @Test
        fun `test when evidence is of type 'object' and without 'type' for v2`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            sampleVcObject.put(EVIDENCE, JSONArray())
            sampleVcObject.getJSONArray(EVIDENCE).put(0, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$EVIDENCE.$TYPE", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${EVIDENCE.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }
    }

    @Nested
    inner class CredentialSchemaTests{
        @Test
        fun `test when credentialSchema is of type 'object' and invalid for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.put(CREDENTIAL_SCHEMA, "Invalid String Type")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_INVALID_FIELD$CREDENTIAL_SCHEMA", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${CREDENTIAL_SCHEMA.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialSchema is of type 'object' and valid for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_SCHEMA, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when credentialSchema is of type 'object' and 'id' is missing for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val evidenceObject = JSONObject()
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_SCHEMA, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_SCHEMA.$ID", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${CREDENTIAL_SCHEMA.uppercase()}_${ID.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialSchema is of type 'object' and 'type' is missing for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            sampleVcObject.put(CREDENTIAL_SCHEMA, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_SCHEMA.$TYPE", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${CREDENTIAL_SCHEMA.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialSchema object has empty id for v1`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "")
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_SCHEMA, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("$CREDENTIAL_SCHEMA.$ID cannot be null or empty.", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${CREDENTIAL_SCHEMA.uppercase()}_${ID.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialSchema object has empty type for v1`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            evidenceObject.put(TYPE, "")
            sampleVcObject.put(CREDENTIAL_SCHEMA, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("$CREDENTIAL_SCHEMA.$TYPE cannot be null or empty.", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${CREDENTIAL_SCHEMA.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialSchema is of type 'array' and valid for v2`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_SCHEMA, JSONArray())
            sampleVcObject.getJSONArray(CREDENTIAL_SCHEMA).put(0, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when credentialSchema is of type 'array' and 'id' is missing for v2`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val evidenceObject = JSONObject()
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_SCHEMA, JSONArray())
            sampleVcObject.getJSONArray(CREDENTIAL_SCHEMA).put(0, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_SCHEMA.$ID", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${CREDENTIAL_SCHEMA.uppercase()}_${ID.uppercase()}", result.validationErrorCode)

        }

        @Test
        fun `test when credentialSchema is of type 'array' and 'type' is missing for v2`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            sampleVcObject.put(CREDENTIAL_SCHEMA, JSONArray())
            sampleVcObject.getJSONArray(CREDENTIAL_SCHEMA).put(0, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$CREDENTIAL_SCHEMA.$TYPE", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${CREDENTIAL_SCHEMA.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialSchema array has object with empty id for v2`() {
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "")
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(CREDENTIAL_SCHEMA, JSONArray())
            sampleVcObject.getJSONArray(CREDENTIAL_SCHEMA).put(evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("$CREDENTIAL_SCHEMA.$ID cannot be null or empty.", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${CREDENTIAL_SCHEMA.uppercase()}_${ID.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when credentialSchema array has object with empty type for v2`() {
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            evidenceObject.put(TYPE, "")
            sampleVcObject.put(CREDENTIAL_SCHEMA, JSONArray())
            sampleVcObject.getJSONArray(CREDENTIAL_SCHEMA).put(evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("$CREDENTIAL_SCHEMA.$TYPE cannot be null or empty.", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${CREDENTIAL_SCHEMA.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }

    }
    @Nested
    inner class RefreshServiceTests{

        @Test
        fun `test when refreshService is of type 'string' and invalid`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.put(REFRESH_SERVICE, "Invalid String Type")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_INVALID_FIELD$REFRESH_SERVICE", result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${REFRESH_SERVICE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when refreshService is of type 'object' and valid for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(REFRESH_SERVICE, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when refreshService is of type 'object' and 'id' is missing for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val evidenceObject = JSONObject()
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(REFRESH_SERVICE, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$REFRESH_SERVICE.$ID", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${REFRESH_SERVICE.uppercase()}_${ID.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when refreshService is of type 'object' and 'type' is missing for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            sampleVcObject.put(REFRESH_SERVICE, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$REFRESH_SERVICE.$TYPE", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${REFRESH_SERVICE.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when refreshService is of type 'object' and valid for v2`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(REFRESH_SERVICE, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when refreshService is of type 'object' and 'id' is missing for v2`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val evidenceObject = JSONObject()
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(REFRESH_SERVICE, evidenceObject)


            val result = credentialsValidator.validate(sampleVcObject.toString())
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)

        }

        @Test
        fun `test when refreshService is of type 'object' and 'type' is missing for v2`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            sampleVcObject.put(REFRESH_SERVICE, evidenceObject)


            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$REFRESH_SERVICE.$TYPE", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${REFRESH_SERVICE.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)

        }

    }

    @Nested
    inner class TermsOfUseTests{
        @Test
        fun `test when termsOfUse is of type object and valid`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(TERMS_OF_USE, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
        }

        @Test
        fun `test when termsOfUse is of type object and 'id' is missing`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val evidenceObject = JSONObject()
            evidenceObject.put(TYPE, "Type")
            sampleVcObject.put(TERMS_OF_USE, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)

        }

        @Test
        fun `test when termsOfUse is of type object and 'type' is missing`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            val evidenceObject = JSONObject()
            evidenceObject.put(ID, "https://google.com/")
            sampleVcObject.put(TERMS_OF_USE, evidenceObject)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$TERMS_OF_USE.$TYPE", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${TERMS_OF_USE.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)

        }
    }

    @Nested
    inner class ValidityPeriodTests{
        @Test
        fun `test when 'validFrom' is missing`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.remove(VALID_FROM)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)

        }

        @Test
        fun `test when 'validFrom' is not in expected format and invalid`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.put(VALID_FROM, "2024-03-03")

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals(ERROR_VALID_FROM_INVALID, result.validationMessage)
            assertEquals("${ERROR_CODE_INVALID}${VALID_FROM.uppercase()}", result.validationErrorCode)

        }

        @Test
        fun `test when 'validUntil' is not in expected format and invalid`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.put(VALID_UNTIL, "2024-03-03")

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals(ERROR_VALID_UNTIL_INVALID, result.validationMessage)
            assertEquals("${ERROR_CODE_INVALID}${VALID_UNTIL.uppercase()}", result.validationErrorCode)

        }

        @Test
        fun `test when current date comes before validFrom`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.put(VALID_FROM, "2076-12-02T17:36:13.644Z")

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals(ERROR_CURRENT_DATE_BEFORE_VALID_FROM, result.validationMessage)
            assertEquals(ERROR_CODE_CURRENT_DATE_BEFORE_VALID_FROM, result.validationErrorCode)

        }

        @Test
        fun `test when validUntil is missing`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.remove(VALID_UNTIL)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)

        }

        @Test
        fun `test when both validFrom and validUntil are missing`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.remove(VALID_UNTIL)
            sampleVcObject.remove(VALID_FROM)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)

        }

        @Test
        fun `test when vc is expired`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.put(VALID_UNTIL, "2023-12-02T17:36:13.644Z")

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals(ERROR_MESSAGE_VC_EXPIRED, result.validationMessage)
            assertEquals(ERROR_CODE_VC_EXPIRED, result.validationErrorCode)
        }

        @Test
        fun `test when vc is not expired`(){
            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.put(VALID_UNTIL, "2074-12-02T17:36:13.644Z")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)

        }
    }

    @Nested
    inner class IssuanceAndExpirationTests{
        @Test
        fun `test when issuanceDate is missing`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.remove(ISSUANCE_DATE)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$ISSUANCE_DATE", result.validationMessage)
            assertEquals("$ERROR_CODE_MISSING${ISSUANCE_DATE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when issuanceDate comes before currentDate`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.put(ISSUANCE_DATE, "2024-09-02T17:36:13.644Z")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)

        }

        @Test
        fun `test when issuanceDate comes after currentDate`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.put(ISSUANCE_DATE, "2076-09-02T17:36:13.644Z")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals(ERROR_CURRENT_DATE_BEFORE_ISSUANCE_DATE, result.validationMessage)
            assertEquals(ERROR_CODE_CURRENT_DATE_BEFORE_ISSUANCE_DATE, result.validationErrorCode)
        }

        @Test
        fun `test when expirationDate is not in expected format and invalid`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.put(EXPIRATION_DATE, "2034-02-02")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals(ERROR_EXPIRATION_DATE_INVALID, result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${EXPIRATION_DATE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when VC is expired`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.put(EXPIRATION_DATE, "2014-12-02T17:36:13.644Z")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals(ERROR_MESSAGE_VC_EXPIRED, result.validationMessage)
            assertEquals(ERROR_CODE_VC_EXPIRED, result.validationErrorCode)
        }

        @Test
        fun `test when VC is not expired`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.put(EXPIRATION_DATE, "2074-12-02T17:36:13.644Z")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)

        }

        @Test
        fun `test when expirationDate is missing`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)

        }

        @Test
        fun `test when issuanceDate is not in expected format and invalid`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.put(ISSUANCE_DATE, "2024-02-02")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals(ERROR_ISSUANCE_DATE_INVALID, result.validationMessage)
            assertEquals("$ERROR_CODE_INVALID${ISSUANCE_DATE.uppercase()}", result.validationErrorCode)
        }
    }

    @Nested
    inner class ProofTests{
        @Test
        fun `test when proof is missing`(){

            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.remove(PROOF)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$PROOF", result.validationMessage)
            assertEquals("${ERROR_CODE_MISSING}${PROOF.uppercase()}", result.validationErrorCode)

        }

        @Test
        fun `test when jws is not present in proof`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.remove(JWS)

            val result = credentialsValidator.validate(sampleVcDataModel1)

            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
            
        }


        @Test
        fun `test when unsupported algorithm is used in jws`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.getJSONObject(PROOF).put(JWS, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals(ERROR_MESSAGE_ALGORITHM_NOT_SUPPORTED, result.validationMessage)
            assertEquals("${ERROR_CODE_INVALID}${ALGORITHM.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when supported algorithm is used in jws`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.put(JWS, "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJraWQiOiJLYlJXRU9YQ0pVRENWVnVET2ZsSkRQWnAtXzNqMEZvajd1RVZHd19xOEdzIiwiYWxnIjoiUFMyNTYifQ..NEcXf5IuDf0eJcBbtIBsXC2bZeOzNBduWG7Vz9A3ePcvh-SuwggPcCPQLrdgl79ta5bYsKsJSKVSS0Xg-GvlY71I2OzU778Bkq52LIDtSXY3DrxQEvM-BqjKLBB-ScA850pG2gV-k_8nkCPmAdvda_jj2Vlkss7VPB5LI6skWTgM4MOyvlMzZCzqmifqTzHLVgefzfixld7E38X7wxzEZfn2lY_fRfWqcL8pKL_kijTHwdTWLb9hMQtP9vlk2iarbT8TmZqutZD8etd1PBFm7V_izcY9cO75A4N3fVrr6NC50cDHDshPZFS48uTBDK-SSePxibpmq1afaS_VX6kX7A")

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
            
        }

        @Test
        fun `test when proof_type is missing`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.getJSONObject(PROOF).remove(TYPE)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("$ERROR_MISSING_REQUIRED_FIELDS$PROOF.$TYPE", result.validationMessage)
            assertEquals("${ERROR_CODE_MISSING}${PROOF.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
            
        }


        @Test
        fun `test when proof type is not supported`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.getJSONObject(PROOF).put(TYPE, "ASASignature2018")

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals(ERROR_MESSAGE_PROOF_TYPE_NOT_SUPPORTED, result.validationMessage)
            assertEquals("${ERROR_CODE_INVALID}${PROOF.uppercase()}_${TYPE.uppercase()}", result.validationErrorCode)
            

        }

        @Test
        fun `test when proof type is supported`() {
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.getJSONObject(PROOF).put(TYPE, "RsaSignature2018")

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("", result.validationMessage)
            assertEquals("", result.validationErrorCode)
            
        }
    }
    
    @Nested
    inner class ContextTests{
        @Test
        fun `test when context is missing for v1`(){

            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.remove(CONTEXT)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CONTEXT", result.validationMessage)
            assertEquals("${ERROR_CODE_MISSING}${CONTEXT.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when context is not valid for v1`(){

            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.getJSONArray(CONTEXT).put(0, "http://www/google.com")

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals(ERROR_MESSAGE_CONTEXT_FIRST_LINE, result.validationMessage)
            assertEquals("${ERROR_CODE_INVALID}${CONTEXT.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when context is missing for v2`(){

            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.remove(CONTEXT)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$CONTEXT", result.validationMessage)
            assertEquals("${ERROR_CODE_MISSING}${CONTEXT.uppercase()}", result.validationErrorCode)
        }
    }
    
    @Nested
    inner class CredentialIssuerTests{
        @Test
        fun `test when issuer is missing for v1`(){

            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.remove(ISSUER)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$ISSUER", result.validationMessage)
            assertEquals("${ERROR_CODE_MISSING}${ISSUER.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when issuer_id is not valid URI`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.put(ISSUER, "invalid-uri")

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("$ERROR_INVALID_URI${ISSUER}", result.validationMessage)
            assertEquals("${ERROR_CODE_INVALID}${ISSUER.uppercase()}", result.validationErrorCode)
            
        }

        @Test
        fun `test when issuer is missing for v2`(){

            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.remove(ISSUER)

            val result = credentialsValidator.validate(sampleVcObject.toString())
            
            assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$ISSUER", result.validationMessage)
            assertEquals("${ERROR_CODE_MISSING}${ISSUER.uppercase()}", result.validationErrorCode)
        }
    }
    
    @Nested
    inner class CredentialTypeTests{
        @Test
        fun `test when type is missing for v1`(){

            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.remove(TYPE)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$TYPE", result.validationMessage)
            assertEquals("${ERROR_CODE_MISSING}${TYPE.uppercase()}", result.validationErrorCode)

        }
        @Test
        fun `test when type is invalid for v1`(){
            val sampleVcObject = JSONObject(sampleVcDataModel1)
            sampleVcObject.getJSONArray(TYPE).put(0, "SampleVC")
            sampleVcObject.getJSONArray(TYPE).put(1, "UnknownCredentialType")

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals(ERROR_MESSAGE_TYPE_VERIFIABLE_CREDENTIAL, result.validationMessage)
            assertEquals("${ERROR_CODE_INVALID}${TYPE.uppercase()}", result.validationErrorCode)
        }

        @Test
        fun `test when type is missing for v2`(){

            val sampleVcObject = JSONObject(sampleVcDataModel2)
            sampleVcObject.remove(TYPE)

            val result = credentialsValidator.validate(sampleVcObject.toString())

            assertEquals("${ERROR_MISSING_REQUIRED_FIELDS}$TYPE", result.validationMessage)
            assertEquals("${ERROR_CODE_MISSING}${TYPE.uppercase()}", result.validationErrorCode)
        }
    }
    
    @Nested
    inner class OtherValidationTests{
        @Test
        fun `test when JSON parsing fails for credential`() {
            mockkStatic(JSONObject::class)
            val invalidJsonString = """
            {"test": "test"}
        """.trimIndent()

            every { JSONObject(invalidJsonString) } throws Exception("JSON parsing error")

            val result = credentialsValidator.validate(invalidJsonString)

            assertEquals("${EXCEPTION_DURING_VALIDATION}JSON parsing error", result.validationMessage)
            assertEquals(ERROR_CODE_GENERIC, result.validationErrorCode)
        }

        @Test
        fun `test when credential is empty string`(){
            val resultEmpty = credentialsValidator.validate("")

            assertEquals(ERROR_MESSAGE_EMPTY_VC_JSON, resultEmpty.validationMessage)
            assertEquals(ERROR_CODE_EMPTY_VC_JSON, resultEmpty.validationErrorCode)
        }
    }
    
    companion object{

        val sampleVcDataModel1 = """
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
                    "id": "https://ida.mosip.net/credentials/b5d20f0a-a9b8-486a-9d60-fdda68a3ea68",
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

    val sampleVcDataModel2 = """
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
                    "id": "did:jwk:eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6InNpZyIsImFsZyI6IlJTMjU2IiwibiI6Im5LLTkxWXRYVmxrWDJTWnFxUHBMVm44aU43aTNXbXk1SDlXMnViTHBsR1d4dWlKa0c0RW1hQklDaWlvekZuWlBrV3BYcmhleGJiMlBKVFBJQ184X2NKcThWU2g0bGtFLTY1QnpwN1dxemMtOVUxRkROU2xLZ2p3cUk0MDNGQVN2S3B0Y0xhcHZDczIzMFYybGN3S0JDTEZ5TF93RTgzcjBlVUZvd1BTR25kMkhNS0k3ZENEMmlmT0M2blphU3RYMjhJYXl6WFFDa2dxOUpIcl9ISlJaQUduZEVhMzlRVDRYekNITkpuOW9WeDQ1c2xmYnZXRVRXZXJlTVdRTTA2Wmx6amhiQWY4QTFjcU1DRHk1ekR0WUx5WmE2MWdqMi1jUkg5UWczcTEzbWhyV3RWLUFwZ0hhRV9iUFVCS2ZpLXlpelU1SDEwczRLNVpDRHdDVEp1eFlGUSJ9",
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
