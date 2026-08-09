package org.springframework.security.boot.weixin.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

/**
 * Thrown when the WeChat authorization code (jscode) used for authentication has expired.
 *
 * <p>Mapped to the {@link AuthResponseCode#SC_AUTHZ_CODE_EXPIRED} response code.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class WxJsCodeExpiredException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Construct a new exception with the specified detail message.
	 *
	 * @param msg the detail message
	 */
	public WxJsCodeExpiredException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED, msg);
	}

	/**
	 * Construct a new exception with the specified detail message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public WxJsCodeExpiredException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED, msg, t);
	}

}
