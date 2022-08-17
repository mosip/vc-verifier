package io.mosip.vercred.exception;
	

/**
 * The Class ProofDocumentNotFoundException.
 * 
 * @author Dhanendra
 */
public class ProofDocumentNotFoundException extends BaseUncheckedException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new proofDocument not found exception.
	 */
	public ProofDocumentNotFoundException() {
		super();
	}

	/**
	 * Instantiates a new proofDocument not found exception.
	 *
	 * @param message the message
	 */
	public ProofDocumentNotFoundException(String errorCode, String message) {
		super(errorCode, message);
	}

	/**
	 * Instantiates a new proofDocument not found exception.
	 *
	 * @param message the message
	 * @param cause the cause
	 */
	public ProofDocumentNotFoundException(String errorCode, String message, Throwable cause) {
		super(errorCode, message, cause);
	}

    public ProofDocumentNotFoundException(String code, String message, Exception e) {
    }
}