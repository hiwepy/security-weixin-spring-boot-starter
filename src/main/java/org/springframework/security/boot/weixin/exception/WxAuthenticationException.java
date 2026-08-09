/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.weixin.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

/**
 * Generic exception raised when the WeChat third-party authentication service fails.
 *
 * <p>Mapped to the {@link AuthResponseCode#SC_AUTHZ_THIRD_PARTY_SERVICE} response
 * code.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class WxAuthenticationException extends AuthenticationExceptionAdapter {

	/**
	 * Construct a new exception with the specified detail message.
	 * @param msg the detail message
	 */
	public WxAuthenticationException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_THIRD_PARTY_SERVICE, msg);
	}

	/**
	 * Construct a new exception with the specified detail message and root cause.
	 * @param msg the detail message
	 * @param t the root cause
	 */
	public WxAuthenticationException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_THIRD_PARTY_SERVICE, msg, t);
	}

}
