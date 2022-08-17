package io.mosip.vercred.exception;
	

/**
 * The Class ProofDocumentNotFoundException.
 * 
 * @author M1049387
 */
public class ProofTypeNotFoundException extends BaseUncheckedException {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * Instantiates a new apis resource access exception.
	 */
	public ProofTypeNotFoundException() {
		super();
	}

	/**
	 * Instantiates a new apis resource access exception.
	 *
	 * @param message the message
	 */
	public ProofTypeNotFoundException(String errorCode, String message) {
		super(errorCode, message);
	}

	/**
	 * Instantiates a new apis resource access exception.
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