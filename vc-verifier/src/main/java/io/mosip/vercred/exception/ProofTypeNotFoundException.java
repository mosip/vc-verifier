package io.mosip.vercred.exception;
	

/**
 * The Class ProofTypeNotFoundException.
 * 
 * @author Dhanendra
 */
public class ProofTypeNotFoundException extends BaseUncheckedException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new proofType not found exception.
	 */
	public ProofTypeNotFoundException() {
		super();
	}

	/**
	 * Instantiates a new proofType not found exception.
	 *
	 * @param message the message
	 */
	public ProofTypeNotFoundException(String message) {
		super(message);
	}

	/**
	 * Instantiates a new proofType not found exception.
	 *
	 * @param message the message
	 * @param cause the cause
	 */
	public ProofTypeNotFoundException(String errorCode, String message, Throwable cause) {
		super(errorCode, message, cause);
	}

    public ProofTypeNotFoundException(String code, String message, Exception e) {
    }
}