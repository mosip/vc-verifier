import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.CredentialVerifierFactory
import io.mosip.vercred.vcverifier.credentialverifier.types.LdpVerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.types.SdJwtVerifiableCredential
import io.mosip.vercred.vcverifier.credentialverifier.types.msomdoc.MsoMdocVerifiableCredential
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CredentialVerifierFactoryTest {

    private val factory = CredentialVerifierFactory()

    @Test
    fun `should return LdpVerifiableCredential for LDP_VC`() {
        val credential = factory.get(CredentialFormat.LDP_VC)
        assertTrue(credential is LdpVerifiableCredential)
    }

    @Test
    fun `should return MsoMdocVerifiableCredential for MSO_MDOC`() {
        val credential = factory.get(CredentialFormat.MSO_MDOC)
        assertTrue(credential is MsoMdocVerifiableCredential)
    }

    @Test
    fun `should return SdJwtVerifiableCredential for VC_SD_JWT`() {
        val credential = factory.get(CredentialFormat.VC_SD_JWT)
        assertTrue(credential is SdJwtVerifiableCredential)
    }

    @Test
    fun `should return SdJwtVerifiableCredential for DC_SD_JWT`() {
        val credential = factory.get(CredentialFormat.DC_SD_JWT)
        assertTrue(credential is SdJwtVerifiableCredential)
    }
}
