package io.mosip.vercred.exception;
	

/**
 * The Class PubicKeyNotFoundException.
 * 
 * @author Dhanendra
 */
public class PublicKeyNotFoundException extends BaseUncheckedException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new public key not found exception.
	 */
	public PublicKeyNotFoundException() {
		super();
	}

	/**
	 * Instantiates a new public key not found exception.
	 *
	 * @param message the message
	 */
	public PublicKeyNotFoundException(String message) {
		super(message);
	}

	/**
	 * Instantiates a new public key not found exception.
	 *
	 * @param message the message
	 * @param cause the cause
	 */
	public PublicKeyNotFoundException(String errorCode, String message, Throwable cause) {
		super(errorCode, message, cause);
	}

    public PublicKeyNotFoundException(String code, String message, Exception e) {
    }
}