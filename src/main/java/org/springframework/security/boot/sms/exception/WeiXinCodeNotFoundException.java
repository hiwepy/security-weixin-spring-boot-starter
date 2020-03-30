package org.springframework.security.boot.sms.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class WeiXinCodeNotFoundException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeNotFoundException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public WeiXinCodeNotFoundException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeNotFoundException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public WeiXinCodeNotFoundException(String msg, Throwable t) {
		super(msg, t);
	}

}
