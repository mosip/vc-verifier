package io.mosip;

import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.VerificationResult;

import java.util.Objects;

public class Main {
    public static void main(String[] args) {



        System.out.println("Verifying VC from jar");
        CredentialsVerifier verifier = new CredentialsVerifier();
        VerificationResult verificationResult = verifier.verify(SampleConstants.SAMPLE_FARMER_VC, Objects.requireNonNull(CredentialFormat.Companion.fromValue("ldp_vc")));
        System.out.println("Verification Result Status: " + verificationResult.getVerificationStatus());
        System.out.println("Verification Result ErrorCode: " + verificationResult.getVerificationErrorCode());
        System.out.println("Verification Result Message: " + verificationResult.getVerificationMessage());

    }
}
