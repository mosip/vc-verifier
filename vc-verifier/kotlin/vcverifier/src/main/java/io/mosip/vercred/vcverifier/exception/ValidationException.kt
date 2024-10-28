package io.mosip.vercred.vcverifier.exception

class ValidationException(val errorMessage: String, val errorCode: String) : BaseUncheckedException(errorMessage)