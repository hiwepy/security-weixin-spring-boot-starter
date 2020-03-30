package org.springframework.security.boot.weixin.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class WeiXinCodeExpiredException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public WeiXinCodeExpiredException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public WeiXinCodeExpiredException(String msg, Throwable t) {
		super(msg, t);
	}

}
