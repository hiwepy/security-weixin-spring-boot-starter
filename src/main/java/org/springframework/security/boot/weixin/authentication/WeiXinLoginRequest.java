package org.springframework.security.boot.weixin.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 */
public class WeiXinLoginRequest {

	/**
	 * 第三方平台js-sdk获取的编码
	 */
	private String jscode;
	/**
	 * 原始数据字符串
	 */
	private String signature;
	/**
	 * 校验用户信息字符串
	 */
	private String rawData;
	/**
	 * 加密用户数据
	 */
	private String encryptedData;
	/**
	 * 加密算法的初始向量
	 */
	private String iv;
	
	@JsonCreator
	public WeiXinLoginRequest(@JsonProperty("jscode") String jscode, @JsonProperty("signature") String signature,
			@JsonProperty("rawData") String rawData, @JsonProperty("encryptedData") String encryptedData, 
			@JsonProperty("iv") String iv) {
		this.jscode = jscode;
		this.signature = signature;
		this.rawData = rawData;
		this.encryptedData = encryptedData;
		this.iv = iv;
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

}
