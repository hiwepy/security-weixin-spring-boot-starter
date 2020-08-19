package org.springframework.security.boot.weixin.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

@SuppressWarnings("serial")
public class WxJsCodeIncorrectException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeIncorrectException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public WxJsCodeIncorrectException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT, msg);
	}

	/**
	 * Constructs an <code>IdentityCodeIncorrectException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public WxJsCodeIncorrectException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT, msg, t);
	}
}
