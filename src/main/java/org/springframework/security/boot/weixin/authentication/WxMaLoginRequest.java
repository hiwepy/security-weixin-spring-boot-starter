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
 * 微信小程序 Login Request
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class WxMaLoginRequest {

	/**
	 * 第三方平台js-sdk获取的编码
	 */
	protected String jscode;
	/**
	 * 会话密钥
	 */
	protected String sessionKey;
	/**
	 * 第三方平台UnionID（通常指第三方账号体系下用户的唯一ID）
	 */
	protected String unionid;
	/**
	 * 第三方平台OpenID（通常指第三方账号体系下某应用中用户的唯一ID）
	 */
	protected String openid;
	/**
	 * 原始数据字符串
	 */
	protected String signature;
	/**
	 * 校验用户信息字符串
	 */
	protected String rawData;
	/**
	 * 加密用户数据
	 */
	protected String encryptedData;
	/**
	 * 加密算法的初始向量
	 */
	protected String iv;
	/**
	 * 	当前请求使用的token，用于绑定用户
	 */
	protected String token;
	/**
	 * 小程序手机号
	 */
	WxMaPhoneNumberInfo phoneNumberInfo;
	/**
	 * 用户信息
	 */
	protected WxMaUserInfo userInfo;

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
