package io.mosip.vercred.vcverifier

import io.mosip.vercred.vcverifier.constants.CredentialFormat.LDP_VC
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.CONTEXT
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_MISSING
import io.mosip.vercred.vcverifier.constants.CredentialVerifierConstants.ERROR_CODE_VERIFICATION_FAILED
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_GENERIC
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.springframework.util.ResourceUtils
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import io.mosip.vercred.vcverifier.constants.CredentialFormat.MSO_MDOC
import io.mosip.vercred.vcverifier.constants.CredentialFormat.VC_SD_JWT


class CredentialsVerifierTest {

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return true for valid credential validation success`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/PS256SignedMosipVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = CredentialsVerifier().verify(vc, LDP_VC)

        assertEquals("", verificationResult.verificationMessage)
        assertTrue(verificationResult.verificationStatus)
        assertEquals("", verificationResult.verificationErrorCode)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return false for invalid credential validation failure`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/invalidVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = CredentialsVerifier().verify(vc, LDP_VC)

        assertFalse(verificationResult.verificationStatus)
        assertEquals("${ERROR_CODE_MISSING}${CONTEXT.uppercase()}", verificationResult.verificationErrorCode)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return true for valid credential verification success`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/PS256SignedMosipVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = CredentialsVerifier().verify(vc, LDP_VC)

        assertEquals("", verificationResult.verificationMessage)
        assertTrue(verificationResult.verificationStatus)
        assertEquals("", verificationResult.verificationErrorCode)

    }

    @Test
    fun `should return true for valid credential verification success using ES256K`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/ES256KSignedMockVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = CredentialsVerifier().verify(vc, LDP_VC)

        assertEquals("", verificationResult.verificationMessage)
        assertTrue(verificationResult.verificationStatus)
        assertEquals("", verificationResult.verificationErrorCode)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return false for invalid credential verification failure`() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "ldp_vc/tamperedVC.json")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verify = CredentialsVerifier().verify(vc, LDP_VC)

        assertFalse(verify.verificationStatus)
        assertEquals(ERROR_CODE_VERIFICATION_FAILED, verify.verificationErrorCode)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return true for valid credential validation success of msomdoc`() {
        val vc = "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkB2TCCAdUwggF7oAMCAQICFBRDWWSBLltTWt65yytaZ01baoM9MAoGCCqGSM49BAMCMFkxCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTENMAsGA1UEBwwETW9jazENMAsGA1UECgwETW9jazENMAsGA1UECwwETU9jazENMAsGA1UEAwwETW9jazAeFw0yNDEwMjEwNzU2MTBaFw0yNTEwMjEwNzU2MTBaMFkxCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTENMAsGA1UEBwwETW9jazENMAsGA1UECgwETW9jazENMAsGA1UECwwETU9jazENMAsGA1UEAwwETW9jazBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABA8PMic1jzZYunhb2Ymq3eH2qEudb5rBnGMk1RAmFuLbPYBgFhDjdhK7j3ciE16-XfCFHnVEX8cANHw1_XjU2nejITAfMB0GA1UdDgQWBBQmaVJHKU-6Y7m6g6qolUJ3p94yhjAKBggqhkjOPQQDAgNIADBFAiEAwXQgNSUrhHIlPE1N24u5UCRwBTqYKKpJqBlC0niZRHgCIFryTL85LV-hab5RL4YiDpDeNOL6_YyiS-STfjrv-OL4WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggahyUDZzWwyVz1oYQSOSTOl3XfzVAAVi-ILLpwP3DMtUGWCBJiBVoqzuOj8ZRrOsV7DNFe0QBWplIKWMU3aILs8y6lwNYILzO8fswbC_wn7rQYO8eq91XotAltVllVzYTwyYHHWYIAVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjFUMDg6MTE6MTNaaXZhbGlkRnJvbcB0MjAyNC0xMC0yMVQwODoxMToxM1pqdmFsaWRVbnRpbMB0MjAyNS0xMC0yMVQwODoxMToxM1pYQBZJtQ6yPA--sITjOK29mGLGKeG2DEx3qDHQEw99esCHwUnPJtobUfLGHhfmM0nawMZai21LXq5ZEdInOkEDSNRqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYaqRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVleBsyMDI0LTEwLTIxVDA4OjExOjEzLjQ5NTQ3OFrYGFhrpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVleBsyMDI1LTEwLTIxVDA4OjExOjEzLjQ5NTQ3OFrYGFjBpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhqe2lzc3VlX2RhdGU9MjAyNC0xMC0yMVQwODoxMToxMy40OTU0NzhaLCB2ZWhpY2xlX2NhdGVnb3J5X2NvZGU9QSwgZXhwaXJ5X2RhdGU9MjAyNS0xMC0yMVQwODoxMToxMy40OTU0NzhafdgYWFekaGRpZ2VzdElEAWZyYW5kb21Q46GI__EQWetvvOYmVd-9b3FlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXJsZWxlbWVudFZhbHVlZDEyMzPYGFhVpGhkaWdlc3RJRARmcmFuZG9tUIO4lnDW2fm_Utg97twL9mJxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWJNS9gYWFikaGRpZ2VzdElEAGZyYW5kb21QBYNczBataC2MR4om9FAnmHFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRlbGVsZW1lbnRWYWx1ZWoxOTk0LTExLTA22BhYVKRoZGlnZXN0SUQHZnJhbmRvbVBJWZtW3VOzNRpXK0Dyf3LTcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlZkpvc2VwaNgYWFWkaGRpZ2VzdElEBWZyYW5kb21QfzR7XZl5Fiz6lZ0oMqRhlnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVmQWdhdGhh"

        val verificationResult = CredentialsVerifier().verify(vc, MSO_MDOC)

        assertEquals("", verificationResult.verificationMessage)
        assertTrue(verificationResult.verificationStatus)
        assertEquals("", verificationResult.verificationErrorCode)
    }

    @Test
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    fun `should return false for credential validation failure of msomdoc`() {
        val vc = "b2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkB2TCCAdUwggF7oAMCAQICFBRDWWSBLltTWt65yytaZ01baoM9MAoGCCqGSM49BAMCMFkxCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTENMAsGA1UEBwwETW9jazENMAsGA1UECgwETW9jazENMAsGA1UECwwETU9jazENMAsGA1UEAwwETW9jazAeFw0yNDEwMjEwNzU2MTBaFw0yNTEwMjEwNzU2MTBaMFkxCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTENMAsGA1UEBwwETW9jazENMAsGA1UECgwETW9jazENMAsGA1UECwwETU9jazENMAsGA1UEAwwETW9jazBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABA8PMic1jzZYunhb2Ymq3eH2qEudb5rBnGMk1RAmFuLbPYBgFhDjdhK7j3ciE16-XfCFHnVEX8cANHw1_XjU2nejITAfMB0GA1UdDgQWBBQmaVJHKU-6Y7m6g6qolUJ3p94yhjAKBggqhkjOPQQDAgNIADBFAiEAwXQgNSUrhHIlPE1N24u5UCRwBTqYKKpJqBlC0niZRHgCIFryTL85LV-hab5RL4YiDpDeNOL6_YyiS-STfjrv-OL4WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggahyUDZzWwyVz1oYQSOSTOl3XfzVAAVi-ILLpwP3DMtUGWCBJiBVoqzuOj8ZRrOsV7DNFe0QBWplIKWMU3aILs8y6lwNYILzO8fswbC_wn7rQYO8eq91XotAltVllVzYTwyYHHWYIAVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjFUMDg6MTE6MTNaaXZhbGlkRnJvbcB0MjAyNC0xMC0yMVQwODoxMToxM1pqdmFsaWRVbnRpbMB0MjAyNS0xMC0yMVQwODoxMToxM1pYQBZJtQ6yPA--sITjOK29mGLGKeG2DEx3qDHQEw99esCHwUnPJtobUfLGHhfmM0nawMZai21LXq5ZEdInOkEDSNRqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYaqRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVleBsyMDI0LTEwLTIxVDA4OjExOjEzLjQ5NTQ3OFrYGFhrpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVleBsyMDI1LTEwLTIxVDA4OjExOjEzLjQ5NTQ3OFrYGFjBpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhqe2lzc3VlX2RhdGU9MjAyNC0xMC0yMVQwODoxMToxMy40OTU0NzhaLCB2ZWhpY2xlX2NhdGVnb3J5X2NvZGU9QSwgZXhwaXJ5X2RhdGU9MjAyNS0xMC0yMVQwODoxMToxMy40OTU0NzhafdgYWFekaGRpZ2VzdElEAWZyYW5kb21Q46GI__EQWetvvOYmVd-9b3FlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXJsZWxlbWVudFZhbHVlZDEyMzPYGFhVpGhkaWdlc3RJRARmcmFuZG9tUIO4lnDW2fm_Utg97twL9mJxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWJNS9gYWFikaGRpZ2VzdElEAGZyYW5kb21QBYNczBataC2MR4om9FAnmHFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRlbGVsZW1lbnRWYWx1ZWoxOTk0LTExLTA22BhYVKRoZGlnZXN0SUQHZnJhbmRvbVBJWZtW3VOzNRpXK0Dyf3LTcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlZkpvc2VwaNgYWFWkaGRpZ2VzdElEBWZyYW5kb21QfzR7XZl5Fiz6lZ0oMqRhlnFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVmQWdhdGhh"

        val verificationResult = CredentialsVerifier().verify(vc, MSO_MDOC)

        assertFalse(verificationResult.verificationStatus)
        assertEquals(ERROR_CODE_GENERIC, verificationResult.verificationErrorCode)
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should return true for valid sd-jwt with sha 384 algo credential validation success `() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "sd-jwt_vc/sdJwtSha384Alg.txt")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = CredentialsVerifier().verify(vc, VC_SD_JWT)

        assertEquals("", verificationResult.verificationMessage)
        assertTrue(verificationResult.verificationStatus)
        assertEquals("", verificationResult.verificationErrorCode)
    }

    @Test
    @Timeout(value = 10, unit = TimeUnit.SECONDS)
    fun `should return true for valid sd-jwt with sha 512 algo credential validation success `() {
        val file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "sd-jwt_vc/sdJwtSha512Alg.txt")
        val vc = String(Files.readAllBytes(file.toPath()))

        val verificationResult = CredentialsVerifier().verify(vc, VC_SD_JWT)

        assertEquals("", verificationResult.verificationMessage)
        assertTrue(verificationResult.verificationStatus)
        assertEquals("", verificationResult.verificationErrorCode)
    }

}