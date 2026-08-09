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
 * distribu会话miynder the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.weixin.authentication;

import cn.binarywang.wx.miniapp.bean.WxMaPhoneNumberInfo;
import cn.binarywang.wx.miniapp.bean.WxMaUserInfo;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

/**
 * WeChat Mini Program ({@code Ma}) login request payload.
 *
 * <p>Carries the credentials and encrypted data sent by the Mini Program client during
 * a login attempt, such as the {@code jscode}, session key, open id and union id.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class WxMaLoginRequest {

	/**
	 * Authorization code obtained from the third-party js-sdk.
	 */
	protected String jscode;
	/**
	 * Session key returned by the WeChat backend.
	 */
	protected String sessionKey;
	/**
	 * Third-party platform UnionID (the unique user id across the third-party account system).
	 */
	protected String unionid;
	/**
	 * Third-party platform OpenID (the unique user id for a specific application).
	 */
	protected String openid;
	/**
	 * Raw data string used for signature verification.
	 */
	protected String signature;
	/**
	 * User information verification string.
	 */
	protected String rawData;
	/**
	 * Encrypted user data.
	 */
	protected String encryptedData;
	/**
	 * Initial vector of the encryption algorithm.
	 */
	protected String iv;
	/**
	 * Token of the current request, used to bind the WeChat user to a local account.
	 */
	protected String token;
	/**
	 * Phone number info decrypted from the encrypted data.
	 */
	WxMaPhoneNumberInfo phoneNumberInfo;
	/**
	 * Decrypted WeChat Mini Program user info.
	 */
	protected WxMaUserInfo userInfo;

	/**
	 * Construct a login request with all raw fields supplied by the Mini Program client.
	 * @param jscode the authorization code obtained from the js-sdk
	 * @param sessionKey the session key returned by the WeChat backend
	 * @param unionid the third-party platform union id
	 * @param openid the third-party platform open id
	 * @param signature the signature used to verify user info
	 * @param rawData the raw data string used for signature verification
	 * @param encryptedData the encrypted user data
	 * @param iv the initial vector of the encryption algorithm
	 * @param token the token used to bind the WeChat user to a local account
	 */
	@JsonCreator
	@JsonIgnoreProperties(ignoreUnknown = true)
	public WxMaLoginRequest(@JsonProperty("jscode") String jscode,
			@JsonProperty("sessionKey") String sessionKey,
			@JsonProperty("unionid") String unionid,
			@JsonProperty("openid") String openid,
			@JsonProperty("signature") String signature,
			@JsonProperty("rawData") String rawData,
			@JsonProperty("encryptedData") String encryptedData,
			@JsonProperty("iv") String iv,
			@JsonProperty("token") String token ) {
		
		this.jscode = jscode;
		this.sessionKey = sessionKey;
		this.unionid = unionid;
		this.openid = openid;
		this.signature = signature;
		this.rawData = rawData;
		this.encryptedData = encryptedData;
		this.iv = iv;
		this.token = token;
	}

}
