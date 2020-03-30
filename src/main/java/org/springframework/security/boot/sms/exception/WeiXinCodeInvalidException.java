package org.springframework.security.boot.sms.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class WeiXinCodeInvalidException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeInvalidException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public WeiXinCodeInvalidException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeInvalidException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public WeiXinCodeInvalidException(String msg, Throwable t) {
		super(msg, t);
	}

}
