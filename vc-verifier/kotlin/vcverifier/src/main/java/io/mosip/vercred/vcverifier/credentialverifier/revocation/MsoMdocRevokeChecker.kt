package io.mosip.vercred.vcverifier.credentialverifier.revocation

import io.mosip.vercred.vcverifier.credentialverifier.RevocationChecker
import java.util.logging.Logger

class MsoMdocRevokeChecker : RevocationChecker {
    private val logger = Logger.getLogger(MsoMdocRevokeChecker::class.java.name)

    override fun isRevoked(credential: String): Boolean {
        logger.info("Started revocation check for mso_mdoc")

        // TODO: Implement revocation check logic for mso_mdoc credentials.


        // For now, return false to indicate "not revoked" by default.
        return false
    }
}
