package org.springframework.security.boot.weixin.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

@SuppressWarnings("serial")
public class WxJsCodeInvalidException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeInvalidException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public WxJsCodeInvalidException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_CODE_INVALID, msg);
	}

	/**
	 * Constructs an <code>IdentityCodeInvalidException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public WxJsCodeInvalidException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_CODE_INVALID, msg, t);
	}

}
