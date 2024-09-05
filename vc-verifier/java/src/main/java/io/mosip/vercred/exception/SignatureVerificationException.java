package io.mosip.vercred.exception;
	

/**
 * The Class SignatureVerificationException.
 */
public class SignatureVerificationException extends BaseUncheckedException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new Signature Verification exception.
	 */
	public SignatureVerificationException() {
		super();
	}

	/**
	 * Instantiates a new Signature Verification exception.
	 *
	 * @param message the message
	 */
	public SignatureVerificationException(String message) {
		super(message);
	}

	/**
	 * Instantiates a new Signature Verification exception.
	 *
	 * @param message the message
	 * @param cause the cause
	 */
	public SignatureVerificationException(String errorCode, String message, Throwable cause) {
		super(errorCode, message, cause);
	}

    public SignatureVerificationException(String code, String message, Exception e) {
    }
}