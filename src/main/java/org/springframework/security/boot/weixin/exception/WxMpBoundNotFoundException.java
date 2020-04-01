package org.springframework.security.boot.weixin.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class WxMpBoundNotFoundException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeNotFoundException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public WxMpBoundNotFoundException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeNotFoundException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public WxMpBoundNotFoundException(String msg, Throwable t) {
		super(msg, t);
	}

}
