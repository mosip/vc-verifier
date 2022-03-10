package io.mosip.vercred.contant;

public class CredentialVerifierConstants {

    public static final String SIGNATURE_SUITE_TERM = "RsaSignature2018";
    

    public static final String PUBLIC_KEY_PEM = "publicKeyPem";

    public static final String JWS_PS256_SIGN_ALGO_CONST = "PS256";

	public static final String JWS_RS256_SIGN_ALGO_CONST = "RS256";

    public static final String RS256_ALGORITHM = "SHA256withRSA";

	public static final String PS256_ALGORITHM = "RSASSA-PSS";

	public static final String PSS_PARAM_SHA_256 = "SHA-256";  

	public static final String PSS_PARAM_MGF1 = "MGF1";

	public static final int PSS_PARAM_SALT_LEN = 32;

	public static final int PSS_PARAM_TF = 1;
}
