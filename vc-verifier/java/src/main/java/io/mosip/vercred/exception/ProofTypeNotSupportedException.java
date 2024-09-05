package io.mosip.vercred.exception;
	

/**
 * The Class ProofTypeNotFoundException.
 * 
 * @author Dhanendra
 */
public class ProofTypeNotSupportedException extends BaseUncheckedException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new proofType not found exception.
	 */
	public ProofTypeNotSupportedException() {
		super();
	}

	/**
	 * Instantiates a new proofType not found exception.
	 *
	 * @param message the message
	 */
	public ProofTypeNotSupportedException(String message) {
		super(message);
	}

	/**
	 * Instantiates a new proofType not found exception.
	 *
	 * @param message the message
	 * @param cause the cause
	 */
	public ProofTypeNotSupportedException(String errorCode, String message, Throwable cause) {
		super(errorCode, message, cause);
	}

    public ProofTypeNotSupportedException(String code, String message, Exception e) {
    }
}