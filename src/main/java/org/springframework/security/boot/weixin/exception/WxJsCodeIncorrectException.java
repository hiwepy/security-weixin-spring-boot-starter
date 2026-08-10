package org.springframework.security.boot.weixin.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

/**
 * Thrown when the WeChat authorization code (jscode) supplied for authentication is incorrect.
 *
 * <p>Mapped to the {@link AuthResponseCode#SC_AUTHZ_CODE_INCORRECT} response code.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@SuppressWarnings("serial")
public class WxJsCodeIncorrectException extends AuthenticationExceptionAdapter {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Construct a new exception with the specified detail message.
	 *
	 * @param msg the detail message
	 */
	public WxJsCodeIncorrectException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT, msg);
	}

	/**
	 * Construct a new exception with the specified detail message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public WxJsCodeIncorrectException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT, msg, t);
	}
}
