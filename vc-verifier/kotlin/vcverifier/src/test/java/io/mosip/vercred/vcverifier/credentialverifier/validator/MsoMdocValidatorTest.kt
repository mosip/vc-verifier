package io.mosip.vercred.vcverifier.credentialverifier.validator

import android.os.Build
import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockkObject
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_CODE_INVALID_DATE_MSO
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants.ERROR_MESSAGE_INVALID_DATE_MSO
import io.mosip.vercred.vcverifier.exception.UnknownException
import io.mosip.vercred.vcverifier.exception.ValidationException
import io.mosip.vercred.vcverifier.utils.BuildConfig
import io.mosip.vercred.vcverifier.utils.DateUtils
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.Date

class MsoMdocValidatorTest {
    @BeforeEach
    fun setUp() {
        mockkObject(BuildConfig)
        every { BuildConfig.getVersionSDKInt() } returns Build.VERSION_CODES.O

        mockkObject(DateUtils)
        every { DateUtils.parseDate("2024-10-23T07:01:17Z") } returns Date(1729666877000L)
        every { DateUtils.parseDate("2026-10-23T07:01:17Z") } returns Date(1792738877000L)

    }

    @AfterEach
    fun after() {
        clearAllMocks()
    }

    @Test
    fun `should return true when credential is successfully validated`() {
        every { DateUtils.isDatePassedCurrentDate("2024-10-23T07:01:17Z") } returns true
        every { DateUtils.isDatePassedCurrentDate("2026-10-23T07:01:17Z") } returns false

        val isVerified = MsoMdocValidator().validate(
            "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkBxDCCAcAwggFloAMCAQICFH6lICTsAhkMivItOT9v6JeZubwmMAoGCCqGSM49BAMCME4xCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTERMA8GA1UEBwwITW9ja0NpdHkxDTALBgNVBAoMBE1vY2sxDTALBgNVBAsMBE1vY2swHhcNMjQxMDIyMDcwMjUwWhcNMjUxMDIyMDcwMjUwWjBOMQswCQYDVQQGEwJNSzEOMAwGA1UECAwFTUstS0ExETAPBgNVBAcMCE1vY2tDaXR5MQ0wCwYDVQQKDARNb2NrMQ0wCwYDVQQLDARNb2NrMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjtRcOXgIyR_xqGB-M6d0qkrjQWOBGGdlPgfIfb2xW0egZAVEz_55IXCofWaprRGxX7qQTlNAZyByniay2jzhR6MhMB8wHQYDVR0OBBYEFNqAHypQYcwWoeUfmMv4SbztomFvMAoGCCqGSM49BAMCA0kAMEYCIQDsgsz9wCa56ukpfyvq9371b5GhkSZb38G7xFofWgFtJwIhAKxACllIOtcleKETDFGa3araADjKd2isahQtXZwQmPr1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggd4bqGFzNwBXyzdGmeipRMfjTQKQuzs6nvM7Z1AXsFBQGWCCaGHxiAeoHvfCNpkG3XpGTTQ787Fg9f3R9UTvKGa0mqwNYICnPRqwtKq9fYqI0sR96Ha3151joEQb24VAzTK4jw8puAVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjNUMDc6MDE6MTdaaXZhbGlkRnJvbcB0MjAyNC0xMC0yM1QwNzowMToxN1pqdmFsaWRVbnRpbMB0MjAyNi0xMC0yM1QwNzowMToxN1pYQOkgtaSchZRTPO01AjYgnKBT9mgXG4NUWsp_W5pCxz5eyB6SIpL9lVYg3tPOkTfYggsVSgPO8ostvTXn7DsBRl5qbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYWKRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVlajIwMjQtMTAtMjPYGFhZpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVlajIwMjktMTAtMjPYGFifpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyNC0xMC0yMywgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwMjktMTAtMjN92BhYV6RoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVkMTIzM9gYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYk1L2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE="
        )

        assertTrue(isVerified)
    }

    @Test
    fun `should throw exception when current time is greater than validFrom`() {
        every { DateUtils.isDatePassedCurrentDate("2024-10-23T07:01:17Z") } returns false
        every { DateUtils.isDatePassedCurrentDate("2026-10-23T07:01:17Z") } returns false
        val verificationException = assertThrows(ValidationException::class.java){
            MsoMdocValidator().validate("omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkBxDCCAcAwggFloAMCAQICFH6lICTsAhkMivItOT9v6JeZubwmMAoGCCqGSM49BAMCME4xCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTERMA8GA1UEBwwITW9ja0NpdHkxDTALBgNVBAoMBE1vY2sxDTALBgNVBAsMBE1vY2swHhcNMjQxMDIyMDcwMjUwWhcNMjUxMDIyMDcwMjUwWjBOMQswCQYDVQQGEwJNSzEOMAwGA1UECAwFTUstS0ExETAPBgNVBAcMCE1vY2tDaXR5MQ0wCwYDVQQKDARNb2NrMQ0wCwYDVQQLDARNb2NrMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjtRcOXgIyR_xqGB-M6d0qkrjQWOBGGdlPgfIfb2xW0egZAVEz_55IXCofWaprRGxX7qQTlNAZyByniay2jzhR6MhMB8wHQYDVR0OBBYEFNqAHypQYcwWoeUfmMv4SbztomFvMAoGCCqGSM49BAMCA0kAMEYCIQDsgsz9wCa56ukpfyvq9371b5GhkSZb38G7xFofWgFtJwIhAKxACllIOtcleKETDFGa3araADjKd2isahQtXZwQmPr1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggd4bqGFzNwBXyzdGmeipRMfjTQKQuzs6nvM7Z1AXsFBQGWCCaGHxiAeoHvfCNpkG3XpGTTQ787Fg9f3R9UTvKGa0mqwNYICnPRqwtKq9fYqI0sR96Ha3151joEQb24VAzTK4jw8puAVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjNUMDc6MDE6MTdaaXZhbGlkRnJvbcB0MjAyNC0xMC0yM1QwNzowMToxN1pqdmFsaWRVbnRpbMB0MjAyNi0xMC0yM1QwNzowMToxN1pYQOkgtaSchZRTPO01AjYgnKBT9mgXG4NUWsp_W5pCxz5eyB6SIpL9lVYg3tPOkTfYggsVSgPO8ostvTXn7DsBRl5qbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYWKRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVlajIwMjQtMTAtMjPYGFhZpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVlajIwMjktMTAtMjPYGFifpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyNC0xMC0yMywgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwMjktMTAtMjN92BhYV6RoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVkMTIzM9gYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYk1L2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE=")
        }

        assertEquals(ERROR_MESSAGE_INVALID_DATE_MSO,verificationException.errorMessage)
        assertEquals(ERROR_CODE_INVALID_DATE_MSO,verificationException.errorCode)
    }

    @Test
    fun `should throw exception when current time is less than validUntil`() {
        every { DateUtils.isDatePassedCurrentDate("2024-10-23T07:01:17Z") } returns true
        every { DateUtils.isDatePassedCurrentDate("2026-10-23T07:01:17Z") } returns true

        val verificationException = assertThrows(ValidationException::class.java){
            MsoMdocValidator().validate("omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkBxDCCAcAwggFloAMCAQICFH6lICTsAhkMivItOT9v6JeZubwmMAoGCCqGSM49BAMCME4xCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTERMA8GA1UEBwwITW9ja0NpdHkxDTALBgNVBAoMBE1vY2sxDTALBgNVBAsMBE1vY2swHhcNMjQxMDIyMDcwMjUwWhcNMjUxMDIyMDcwMjUwWjBOMQswCQYDVQQGEwJNSzEOMAwGA1UECAwFTUstS0ExETAPBgNVBAcMCE1vY2tDaXR5MQ0wCwYDVQQKDARNb2NrMQ0wCwYDVQQLDARNb2NrMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjtRcOXgIyR_xqGB-M6d0qkrjQWOBGGdlPgfIfb2xW0egZAVEz_55IXCofWaprRGxX7qQTlNAZyByniay2jzhR6MhMB8wHQYDVR0OBBYEFNqAHypQYcwWoeUfmMv4SbztomFvMAoGCCqGSM49BAMCA0kAMEYCIQDsgsz9wCa56ukpfyvq9371b5GhkSZb38G7xFofWgFtJwIhAKxACllIOtcleKETDFGa3araADjKd2isahQtXZwQmPr1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggd4bqGFzNwBXyzdGmeipRMfjTQKQuzs6nvM7Z1AXsFBQGWCCaGHxiAeoHvfCNpkG3XpGTTQ787Fg9f3R9UTvKGa0mqwNYICnPRqwtKq9fYqI0sR96Ha3151joEQb24VAzTK4jw8puAVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjNUMDc6MDE6MTdaaXZhbGlkRnJvbcB0MjAyNC0xMC0yM1QwNzowMToxN1pqdmFsaWRVbnRpbMB0MjAyNi0xMC0yM1QwNzowMToxN1pYQOkgtaSchZRTPO01AjYgnKBT9mgXG4NUWsp_W5pCxz5eyB6SIpL9lVYg3tPOkTfYggsVSgPO8ostvTXn7DsBRl5qbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYWKRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVlajIwMjQtMTAtMjPYGFhZpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVlajIwMjktMTAtMjPYGFifpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyNC0xMC0yMywgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwMjktMTAtMjN92BhYV6RoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVkMTIzM9gYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYk1L2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE=")
        }

        assertEquals(ERROR_MESSAGE_INVALID_DATE_MSO,verificationException.errorMessage)
        assertEquals(ERROR_CODE_INVALID_DATE_MSO,verificationException.errorCode)
    }

    @Test
    fun `should throw exception string when issuerAuth is not available`() {
        assertThrows(UnknownException::class.java){
            MsoMdocValidator().validate(
                "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSham5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xiNgYWFWkaGRpZ2VzdElEAmZyYW5kb21QbYUstb5qYaqaDGEXvWdD53FlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZWxlbGVtZW50VmFsdWVmQWdhdGhh2BhYVKRoZGlnZXN0SUQGZnJhbmRvbVDcl4VzmY5oXohcs2H4bJdGcWVsZW1lbnRJZGVudGlmaWVyamdpdmVuX25hbWVsZWxlbWVudFZhbHVlZkpvc2VwaNgYWIGkaGRpZ2VzdElEA2ZyYW5kb21QIL6_sBEAsnZUVxjDD0BsyHFlbGVtZW50SWRlbnRpZmllcmpiaXJ0aF9kYXRlbGVsZW1lbnRWYWx1ZVgyrO0ABXNyAA1qYXZhLnRpbWUuU2VylV2EuhsiSLIMAAB4cHcNAgAAAAA5hMGAAAAAAHjYGFhqpGhkaWdlc3RJRAFmcmFuZG9tUOOhiP_xEFnrb7zmJlXfvW9xZWxlbWVudElkZW50aWZpZXJqaXNzdWVfZGF0ZWxlbGVtZW50VmFsdWV4GzIwMjQtMTAtMDhUMDI6MDc6NTkuMjI2OTYwWtgYWGukaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZWxlbGVtZW50VmFsdWV4GzIwMjQtMTAtMjBUMDI6MDc6NTkuMjI2OTYwWtgYWFmkaGRpZ2VzdElEAGZyYW5kb21QBYNczBataC2MR4om9FAnmHFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlZklzbGFuZNgYWFSkaGRpZ2VzdElEB2ZyYW5kb21QSVmbVt1TszUaVytA8n9y03FlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXJsZWxlbWVudFZhbHVlGHvYGFkBUaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVycmRyaXZpbmdfcHJpdmlsZWdlc2xlbGVtZW50VmFsdWVY-qztAAVzcgAXamF2YS51dGlsLkxpbmtlZEhhc2hNYXA0wE5cEGzA-wIAAVoAC2FjY2Vzc09yZGVyeHIAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA_QAAAAAAABncIAAAACAAAAAN0ABV2ZWhpY2xlX2NhdGVnb3J5X2NvZGV0AAFBdAAKaXNzdWVfZGF0ZXQAGzIwMjQtMTAtMDhUMDI6MDc6NTkuMjI2OTYwWnQAC2V4cGlyeV9kYXRldAAbMjAyNC0xMC0yMFQwMjowNzo1OS4yMjY5NjBaeAA"
            )
        }
    }

    @Test
    fun `should throw exception when credential is not properly base64 url encoded`() {
        val exception = assertThrows(UnknownException::class.java) {
            MsoMdocValidator().validate(
                "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkBxDCCAcAwggFloAMCAQICFH6lICTsAhkMivItOT9v6JeZubwmMAoGCCqGSM49BAMCME4xCzAJBgNVBAYTAk1LMQ4wDAYDVQQIDAVNSy1LQTERMA8GA1UEBwwITW9ja0NpdHkxDTALBgNVBAoMBE1vY2sxDTALBgNVBAsMBE1vY2swHhcNMjQxMDIyMDcwMjUwWhcNMjUxMDIyMDcwMjUwWjBOMQswCQYDVQQGEwJNSzEOMAwGA1UECAwFTUstS0ExETAPBgNVBAcMCE1vY2tDaXR5MQ0wCwYDVQQKDARNb2NrMQ0wCwYDVQQLDARNb2NrMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjtRcOXgIyR_xqGB-M6d0qkrjQWOBGGdlPgfIfb2xW0egZAVEz_55IXCofWaprRGxX7qQTlNAZyByniay2jzhR6MhMB8wHQYDVR0OBBYEFNqAHypQYcwWoeUfmMv4SbztomFvMAoGCCqGSM49BAMCA0kAMEYCIQDsgsz9wCa56ukpfyvq9371b5GhkSZb38G7xFofWgFtJwIhAKxACllIOtcleKETDFGa3araADjKd2isahQtXZwQmPr1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggd4bqGFzNwBXyzdGmeipRMfjTQKQuzs6nvM7Z1AXsFBQGWCCaGHxiAeoHvfCNpkG3XpGTTQ787Fg9f3R9UTvKGa0mqwNYICnPRqwtKq9fYqI0sR96Ha3151joEQb24VAzTK4jw8puAVggHp8Y6cV73O670tvfMiyCZoxGczcYyfOh43Q8ahKpxxcEWCC75BhZBjDE1I4S5NLZAsaUmBERMZM9rMgZPkAzl45VeABYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYIOMdpjABg7S1sJBCgdC4D6V237Jk_oGhMl_LInX0CFnGIlggPdyNKVXrSZb4CYQmoK6lX7Zux0DIBcnhJ9-_a7ZlYtdsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjQtMTAtMjNUMDc6MDE6MTdaaXZhbGlkRnJvbcB0MjAyNC0xMC0yM1QwNzowMToxN1pqdmFsaWRVbnRpbMB0MjAyNi0xMC0yM1QwNzowMToxN1pYQOkgtaSchZRTPO01AjYgnKBT9mgXG4NUWsp_W5pCxz5eyB6SIpL9lVYg3tPOkTfYggsVSgPO8ostvTXn7DsBRl5qbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYWKRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVlajIwMjQtMTAtMjPYGFhZpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVlajIwMjktMTAtMjPYGFifpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyNC0xMC0yMywgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwMjktMTAtMjN92BhYRoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVkMTIzM9gYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYk1L2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE="
            )
        }

        assertEquals("Error while doing validation of credential - Error on decoding base64Url encoded data Last unit does not have enough valid bits",exception.message)
    }
}