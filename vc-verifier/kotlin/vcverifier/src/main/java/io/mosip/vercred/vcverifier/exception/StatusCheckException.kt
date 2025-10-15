package io.mosip.vercred.vcverifier.exception

class StatusCheckException(message: String?, errorCode: StatusCheckErrorCode) : BaseUncheckedException(message)

enum class StatusCheckErrorCode {
    STATUS_LIST_LENGTH_ERROR,
    RANGE_ERROR,
    STATUS_VERIFICATION_ERROR,
    STATUS_RETRIEVAL_ERROR,
    INVALID_PURPOSE,
    INVALID_INDEX,
    ENCODED_LIST_MISSING,
    BASE64_DECODE_FAILED,
    GZIP_DECOMPRESS_FAILED,
    UNKNOWN_ERROR
}