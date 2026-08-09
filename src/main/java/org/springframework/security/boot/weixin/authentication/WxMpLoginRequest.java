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
package org.springframework.security.boot.weixin.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import me.chanjar.weixin.common.bean.WxOAuth2UserInfo;
import me.chanjar.weixin.common.bean.oauth2.WxOAuth2AccessToken;

/**
 * WeChat Public Account ({@code Mp}) login request payload.
 *
 * <p>Carries the OAuth2 authorization data exchanged during a Public Account web
 * login. See the
 * <a href="https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html">
 * official documentation</a>.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class WxMpLoginRequest {

	/**
	 * OAuth2 authorization code used to exchange for an access token.
	 */
	protected String code;

	/**
	 * Token of the current request, used to bind the WeChat user to a local account.
	 */
	protected String token;

	/**
	 * OAuth2 state parameter echoed back from the WeChat authorization server.
	 */
	protected String state;
	/**
	 * Third-party platform UnionID (the unique user id across the third-party account system).
	 */
	protected String unionid;
	/**
	 * Third-party platform OpenID (the unique user id for a specific application).
	 */
	protected String openid;
	/**
	 * Preferred user language, one of {@code zh_CN}, {@code zh_TW} or {@code en}.
	 */
	protected String lang = "zh_CN";
	/**
	 * Web authorization access token used to invoke WeChat APIs.
	 */
	protected WxOAuth2AccessToken accessToken;
	/**
	 * WeChat user info resolved from the access token.
	 */
	protected WxOAuth2UserInfo userInfo;

	/**
	 * Construct a login request with the OAuth2 fields supplied by the front end.
	 * @param code the OAuth2 authorization code
	 * @param state the OAuth2 state parameter
	 * @param token the token used to bind the WeChat user to a local account
	 */
	@JsonCreator
	@JsonIgnoreProperties(ignoreUnknown = true)
	public WxMpLoginRequest(@JsonProperty("code") String code,
			@JsonProperty("state") String state,
			@JsonProperty("token") String token) {
		this.code = code;
		this.state = state;
		this.token = token;
	}

}
