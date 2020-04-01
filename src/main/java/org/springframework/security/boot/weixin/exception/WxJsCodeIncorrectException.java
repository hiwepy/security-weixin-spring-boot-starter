package org.springframework.security.boot.weixin.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class WxJsCodeIncorrectException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeIncorrectException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public WxJsCodeIncorrectException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeIncorrectException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public WxJsCodeIncorrectException(String msg, Throwable t) {
		super(msg, t);
	}
}
