package io.mosip.vercred;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Objects;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.JWSObject;

import io.mosip.vercred.exception.ProofDocumentNotFoundException;
import io.mosip.vercred.exception.ProofTypeNotFoundException;
import io.mosip.vercred.exception.PubicKeyNotFoundException;
import io.mosip.vercred.exception.UnknownException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RestTemplate;

import foundation.identity.jsonld.ConfigurableDocumentLoader;
import foundation.identity.jsonld.JsonLDException;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.canonicalizer.URDNA2015Canonicalizer;
import info.weboftrust.ldsignatures.util.JWSUtil;
import io.mosip.vercred.contant.CredentialVerifierConstants;

public class CredentialsVerifier {

    Logger CredVerifierLogger = LoggerFactory.getLogger(CredentialsVerifier.class);

    @Autowired
	private RestTemplate restTemplate;
    
    public boolean verifyCredentials(String credentials){
        CredVerifierLogger.info("Received Credentials Verification - Start.");
        ConfigurableDocumentLoader confDocumentLoader = new ConfigurableDocumentLoader();
		confDocumentLoader.setEnableHttps(true);
		confDocumentLoader.setEnableHttp(true);
		confDocumentLoader.setEnableFile(false);

        JsonLDObject vcJsonLdObject = JsonLDObject.fromJson(credentials);
        vcJsonLdObject.setDocumentLoader(confDocumentLoader);

        LdProof ldProofWithJWS = LdProof.getFromJsonLDObject(vcJsonLdObject);
        if (Objects.isNull(ldProofWithJWS)) {
            CredVerifierLogger.error("Proof document is not available in the received credentials.");
            return false;
        }

        String ldProofTerm = ldProofWithJWS.getType();
        if (!CredentialVerifierConstants.SIGNATURE_SUITE_TERM.equals(ldProofTerm)) {
            CredVerifierLogger.error("Proof Type available in received credentials is not matching " + 
                            " with supported proof terms. Recevied Type: {}", ldProofTerm);
            return false;
        }
        
		try {

            URDNA2015Canonicalizer canonicalizer =	new URDNA2015Canonicalizer();
            byte[] canonicalHashBytes = canonicalizer.canonicalize(ldProofWithJWS, vcJsonLdObject);
            CredVerifierLogger.info("Completed Canonicalization for the received credentials.");
            String signJWS = ldProofWithJWS.getJws();
            JWSObject jwsObject = JWSObject.parse(signJWS);
            byte[] vcSignBytes = jwsObject.getSignature().decode();
            URI publicKeyJsonUri = ldProofWithJWS.getVerificationMethod();
            PublicKey publicKeyObj = getPublicKeyFromVerificationMethod(publicKeyJsonUri);
            if (Objects.isNull(publicKeyObj)) {
                CredVerifierLogger.error("Public key object is null, returning false.");
                return false;
            }
            CredVerifierLogger.info("Completed downloading public key from the issuer domain and constructed public key object.");
            byte[] actualData = JWSUtil.getJwsSigningInput(jwsObject.getHeader(), canonicalHashBytes);
            String jwsHeader = jwsObject.getHeader().getAlgorithm().getName();
            CredVerifierLogger.info("Performing signature verification after downloading the public key.");
            return verifyCredentialSignature(jwsHeader, publicKeyObj, actualData, vcSignBytes);
        } catch (IOException | GeneralSecurityException | JsonLDException | ParseException e) {
            CredVerifierLogger.error("Error in doing verifiable credential verification process.", e);
        }	
        return false;
    }

    public boolean verifyPrintCredentials(String credentials){
        CredVerifierLogger.info("Received Credentials Verification - Start.");
        ConfigurableDocumentLoader confDocumentLoader = new ConfigurableDocumentLoader();
        confDocumentLoader.setEnableHttps(true);
        confDocumentLoader.setEnableHttp(true);
        confDocumentLoader.setEnableFile(false);

        JsonLDObject vcJsonLdObject = JsonLDObject.fromJson(credentials);
        vcJsonLdObject.setDocumentLoader(confDocumentLoader);

        LdProof ldProofWithJWS = LdProof.getFromJsonLDObject(vcJsonLdObject);
        if (Objects.isNull(ldProofWithJWS)) {
            CredVerifierLogger.error("Proof document is not available in the received credentials.");
            throw new ProofDocumentNotFoundException("Proof document is not available in the received credentials.");
        }

        String ldProofTerm = ldProofWithJWS.getType();
        if (!CredentialVerifierConstants.SIGNATURE_SUITE_TERM.equals(ldProofTerm)) {
            CredVerifierLogger.error("Proof Type available in received credentials is not matching " +
                    " with supported proof terms. Recevied Type: {}", ldProofTerm);
            throw new ProofTypeNotFoundException("Proof Type available in received credentials is not matching with supported proof terms.");
        }

        try {

            URDNA2015Canonicalizer canonicalizer =	new URDNA2015Canonicalizer();
            byte[] canonicalHashBytes = canonicalizer.canonicalize(ldProofWithJWS, vcJsonLdObject);
            CredVerifierLogger.info("Completed Canonicalization for the received credentials.");
            String signJWS = ldProofWithJWS.getJws();
            JWSObject jwsObject = JWSObject.parse(signJWS);
            byte[] vcSignBytes = jwsObject.getSignature().decode();
            URI publicKeyJsonUri = ldProofWithJWS.getVerificationMethod();
            PublicKey publicKeyObj = getPublicKeyFromVerificationMethod(publicKeyJsonUri);
            if (Objects.isNull(publicKeyObj)) {
                CredVerifierLogger.error("Public key object is null, returning false.");
                throw new PubicKeyNotFoundException("Public key object is null.");
            }
            CredVerifierLogger.info("Completed downloading public key from the issuer domain and constructed public key object.");
            byte[] actualData = JWSUtil.getJwsSigningInput(jwsObject.getHeader(), canonicalHashBytes);
            String jwsHeader = jwsObject.getHeader().getAlgorithm().getName();
            CredVerifierLogger.info("Performing signature verification after downloading the public key.");
            return verifyCredentialSignature(jwsHeader, publicKeyObj, actualData, vcSignBytes);
        } catch (IOException | GeneralSecurityException | JsonLDException | ParseException e) {
            CredVerifierLogger.error("Error in doing verifiable credential verification process.", e);
            throw new UnknownException("Error in doing verifiable credential verification process.");
        }
    }

    private PublicKey getPublicKeyFromVerificationMethod(URI publicKeyJsonUri){
        
        try {
            ObjectNode response = restTemplate.exchange(publicKeyJsonUri, HttpMethod.GET, null, ObjectNode.class).getBody();
            String publicKeyPem = response.get(CredentialVerifierConstants.PUBLIC_KEY_PEM).asText();
            CredVerifierLogger.info("public key download completed.");
            StringReader strReader = new StringReader(publicKeyPem);
            PemReader pemReader = new PemReader(strReader);
            PemObject pemObject = pemReader.readPemObject();
            byte[] pubKeyBytes = pemObject.getContent();
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(pubKeySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            CredVerifierLogger.error("Error Generating public key object.", e);
        }
		return null;
    }

    private boolean verifyCredentialSignature(String algorithm, PublicKey publicKey, byte[] actualData, byte[] signature) {

        if (algorithm.equals(CredentialVerifierConstants.JWS_RS256_SIGN_ALGO_CONST)) {
            try {
                CredVerifierLogger.info("Validating signature using RS256 algorithm.");
                Signature rsSignature = Signature.getInstance(CredentialVerifierConstants.RS256_ALGORITHM);
                rsSignature.initVerify(publicKey);
                rsSignature.update(actualData);
                return rsSignature.verify(signature);
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                CredVerifierLogger.error("Error in Verifying credentials(RS256).", e);
            }
        }
        try {
            CredVerifierLogger.info("Validating signature using PS256 algorithm.");
            Signature psSignature = Signature.getInstance(CredentialVerifierConstants.PS256_ALGORITHM);
                
            PSSParameterSpec pssParamSpec = new PSSParameterSpec(CredentialVerifierConstants.PSS_PARAM_SHA_256, CredentialVerifierConstants.PSS_PARAM_MGF1, 
                        MGF1ParameterSpec.SHA256, CredentialVerifierConstants.PSS_PARAM_SALT_LEN, CredentialVerifierConstants.PSS_PARAM_TF);
            psSignature.setParameter(pssParamSpec);

            psSignature.initVerify(publicKey);
            psSignature.update(actualData);
            return psSignature.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | InvalidAlgorithmParameterException e) {
            CredVerifierLogger.error("Error in Verifying credentials(PS256).", e);
        }
        return false;
    }

}
