package io.mosip.vercred.exception;
	

/**
 * The Class PubicKeyNotFoundException.
 * 
 * @author Dhanendra
 */
public class PubicKeyNotFoundException extends BaseUncheckedException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new public key not found exception.
	 */
	public PubicKeyNotFoundException() {
		super();
	}

	/**
	 * Instantiates a new public key not found exception.
	 *
	 * @param message the message
	 */
	public PubicKeyNotFoundException(String message) {
		super(message);
	}

	/**
	 * Instantiates a new public key not found exception.
	 *
	 * @param message the message
	 * @param cause the cause
	 */
	public PubicKeyNotFoundException(String errorCode, String message, Throwable cause) {
		super(errorCode, message, cause);
	}

    public PubicKeyNotFoundException(String code, String message, Exception e) {
    }
}