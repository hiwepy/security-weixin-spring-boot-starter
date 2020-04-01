package org.springframework.security.boot.weixin.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class WxJsCodeBoundNotFoundException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeNotFoundException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public WxJsCodeBoundNotFoundException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeNotFoundException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public WxJsCodeBoundNotFoundException(String msg, Throwable t) {
		super(msg, t);
	}

}
