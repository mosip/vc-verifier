package io.mosip.vercred.vcverifier.credentialverifier

import io.mosip.vercred.vcverifier.constants.CredentialFormat
import io.mosip.vercred.vcverifier.credentialverifier.RevocationChecker
import io.mosip.vercred.vcverifier.credentialverifier.revocation.LdpRevokeChecker
import io.mosip.vercred.vcverifier.credentialverifier.revocation.MsoMdocRevokeChecker

class RevocationCheckerFactory {
    fun get(credentialFormat: CredentialFormat): RevocationChecker {
        return when (credentialFormat) {
            CredentialFormat.LDP_VC -> LdpRevokeChecker()
            CredentialFormat.MSO_MDOC -> MsoMdocRevokeChecker()
        }
    }
}