package org.springframework.security.boot.weixin.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

@SuppressWarnings("serial")
public class WxJsCodeExpiredException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public WxJsCodeExpiredException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED, msg);
	}

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public WxJsCodeExpiredException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED, msg, t);
	}

}
