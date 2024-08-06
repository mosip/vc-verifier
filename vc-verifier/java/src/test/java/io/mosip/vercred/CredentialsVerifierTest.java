package io.mosip.vercred;

import io.mosip.vercred.exception.ProofDocumentNotFoundException;
import org.junit.Test;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.*;

public class CredentialsVerifierTest {

    @Test
    public void returnTrueIfAValidVerifiableCredentialIsPassed() throws IOException {
        File file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "VerifiableCredential.json");
        String credential = new String(Files.readAllBytes(file.toPath()));
        CredentialsVerifier cv = new CredentialsVerifier();
        boolean data = cv.verifyCredentials(credential);
        assertTrue(data);
    }

    @Test(expected = ProofDocumentNotFoundException.class)
    public void throwProofDocumentNotFoundExceptionIfVerifiableCredentialIsPaasedWithProofObject() throws IOException {
        File file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "VerifiableCredentialWithoutProof.json");
        String credentialWithoutProof = new String(Files.readAllBytes(file.toPath()));
        CredentialsVerifier cv = new CredentialsVerifier();
        cv.verifyCredentials(credentialWithoutProof);
    }

    @Test
    public void returnFalseIfAInValidVerifiableCredentialIsPassed() throws IOException {
        File file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "TamperedVerifiableCredential.json");
        String tamperedCredential = new String(Files.readAllBytes(file.toPath()));
        CredentialsVerifier cv = new CredentialsVerifier();
        boolean data = cv.verifyCredentials(tamperedCredential);
        assertFalse(data);
    }

}