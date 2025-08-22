package io.mosip.vercred.vcverifier.testHelpers

import io.mockk.InternalPlatformDsl.toStr
import org.junit.jupiter.api.Assertions.assertEquals
import java.security.PublicKey

internal fun assertPublicKey(actualPublicKey: PublicKey, expectedEncoded: String){
    assertEquals(expectedEncoded, actualPublicKey.encoded.toStr())
}