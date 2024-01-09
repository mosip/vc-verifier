package io.mosip.tools.vc.verifier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import io.mosip.vercred.CredentialsVerifier;

@Component
public class VCVerifier {
	
	@Autowired
	private CredentialsVerifier credentialsVerifier;
	
	public boolean verify(String credentials) {
		return credentialsVerifier.verifyCredentials(credentials);
	}

}
