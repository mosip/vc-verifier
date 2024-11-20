package io.mosip.vercred.vcverifier.credentialverifier.validator

import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DATE_MSO
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.extractMso
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.DateUtils
import io.mosip.vercred.vcverifier.utils.Logger

class MsoMdocValidator {
    private val loggerName = MsoMdocValidator::class.java.name


    fun validate(credential: String): Boolean {
        try {
            val (_, issuerSigned) = MsoMdocVerifiableCredential().parse(credential)

            /**
            a) The elements in the ‘ValidityInfo’ structure are verified against the current time stamp
             */

            val validityInfo: Map = issuerSigned.issuerAuth.extractMso()["validityInfo"] as Map
            val validFrom: DataItem? = validityInfo["validFrom"]
            val validUntil: DataItem? = validityInfo["validUntil"]
            if (validUntil == null || validFrom == null) {
                Logger.error(loggerName, "validUntil / validFrom is not available in the credential's MSO")
                throw ValidationException(ERROR_MESSAGE_INVALID_DATE_MSO, ERROR_CODE_INVALID_DATE_MSO)
            }
            val isCurrentTimeGreaterThanValidFrom =
                DateUtils.isDatePassedCurrentDate(validFrom.toString())
            val isCurrentTimeLessThanValidUntil =
                !DateUtils.isDatePassedCurrentDate(validUntil.toString())
            val isValidUntilGreaterThanValidFrom: Boolean =
                DateUtils.parseDate(validUntil.toString())?.after(
                    DateUtils.parseDate(
                        validFrom.toString()
                    ) ?: return false
                ) ?: false
            if (!(isCurrentTimeLessThanValidUntil && isCurrentTimeGreaterThanValidFrom && isValidUntilGreaterThanValidFrom)) {
                Logger.error(loggerName, "Error while doing validity verification - invalid validUntil / validFrom in the MSO of the credential")
                throw ValidationException(ERROR_MESSAGE_INVALID_DATE_MSO, ERROR_CODE_INVALID_DATE_MSO)
            }
            return true
        } catch (exception: Exception) {
            when(exception){
                is ValidationException -> throw exception

            }
            throw UnknownException("Error while doing validation of credential - ${exception.message}")
        }
    }
}

operator fun DataItem.get(name: String): DataItem? {
    check(this.majorType == MajorType.MAP)
    this as Map
    if (this.keys.contains(UnicodeString(name)))
        return this.get(UnicodeString(name))
    return null
}