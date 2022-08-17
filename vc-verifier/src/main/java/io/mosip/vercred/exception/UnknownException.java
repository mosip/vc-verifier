package io.mosip.vercred.exception;
	

/**
 * The Class UnknownException.
 * 
 * @author Dhanendra
 */
public class UnknownException extends BaseUncheckedException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new unknown exception.
	 */
	public UnknownException() {
		super();
	}

	/**
	 * Instantiates a new unknown exception.
	 *
	 * @param message the message
	 */
	public UnknownException(String message) {
		super(message);
	}

	/**
	 * Instantiates a new unknown exception.
	 *
	 * @param message the message
	 * @param cause the cause
	 */
	public UnknownException(String errorCode, String message, Throwable cause) {
		super(errorCode, message, cause);
	}

    public UnknownException(String code, String message, Exception e) {
    }
}