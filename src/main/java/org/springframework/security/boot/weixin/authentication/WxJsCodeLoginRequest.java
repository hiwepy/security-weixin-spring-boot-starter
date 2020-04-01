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
import com.fasterxml.jackson.annotation.JsonProperty;

import cn.binarywang.wx.miniapp.bean.WxMaUserInfo;

/**
 * 微信小程序 Login Request
 * 
 * @author ： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class WxJsCodeLoginRequest {

	/**
	 * 第三方平台js-sdk获取的编码
	 */
	protected String jscode;
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
	 * 用户信息
	 */
	protected WxMaUserInfo userInfo;

	@JsonCreator
	public WxJsCodeLoginRequest(@JsonProperty("jscode") String jscode, @JsonProperty("signature") String signature,
			@JsonProperty("rawData") String rawData, @JsonProperty("encryptedData") String encryptedData, 
			@JsonProperty("iv") String iv, @JsonProperty("userInfo") WxMaUserInfo userInfo) {
		this.jscode = jscode;
		this.signature = signature;
		this.rawData = rawData;
		this.encryptedData = encryptedData;
		this.iv = iv;
		this.userInfo = userInfo;
	}
	
	public String getJscode() {
		return jscode;
	}

	public void setJscode(String jscode) {
		this.jscode = jscode;
	}

	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	public String getRawData() {
		return rawData;
	}

	public void setRawData(String rawData) {
		this.rawData = rawData;
	}

	public String getEncryptedData() {
		return encryptedData;
	}

	public void setEncryptedData(String encryptedData) {
		this.encryptedData = encryptedData;
	}

	public String getIv() {
		return iv;
	}

	public void setIv(String iv) {
		this.iv = iv;
	}

	public WxMaUserInfo getUserInfo() {
		return userInfo;
	}

	public void setUserInfo(WxMaUserInfo userInfo) {
		this.userInfo = userInfo;
	}

}
