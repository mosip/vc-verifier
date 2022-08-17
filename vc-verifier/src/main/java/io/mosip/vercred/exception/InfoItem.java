package io.mosip.vercred.exception;


import java.io.Serializable;

/**
 * This class is the entity class for the BaseUncheckedException and
 * BaseCheckedException class.
 * 
 * @author Shashank Agrawal
 * @since 1.0
 */
class InfoItem implements Serializable {

	private static final long serialVersionUID = -779695043380592601L;

	public String errorCode = null;


	public String errorText = null;

	public InfoItem(String errorCode, String errorText) {
	}
}
