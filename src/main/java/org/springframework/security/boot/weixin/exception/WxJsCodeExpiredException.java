package org.springframework.security.boot.weixin.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class WxJsCodeExpiredException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public WxJsCodeExpiredException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public WxJsCodeExpiredException(String msg, Throwable t) {
		super(msg, t);
	}

}
