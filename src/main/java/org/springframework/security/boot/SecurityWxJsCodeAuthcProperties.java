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
package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecurityRedirectProperties;
import org.springframework.security.boot.weixin.authentication.WxJsCodeAuthenticationProcessingFilter;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(SecurityWxJsCodeAuthcProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityWxJsCodeAuthcProperties extends SecurityAuthcProperties {

	public static final String PREFIX = "spring.security.weixin.ma";
	
	/** the jscode parameter name. Defaults to "jscode". */
    private String jscodeParameter = WxJsCodeAuthenticationProcessingFilter.SPRING_SECURITY_FORM_JSCODE_KEY;
    /** the signature parameter name. Defaults to "signature". */
    private String signatureParameter = WxJsCodeAuthenticationProcessingFilter.SPRING_SECURITY_FORM_SIGNATURE_KEY;
    /** the rawData parameter name. Defaults to "rawData". */
    private String rawDataParameter = WxJsCodeAuthenticationProcessingFilter.SPRING_SECURITY_FORM_RAWDATA_KEY;
    /** the encryptedData parameter name. Defaults to "encryptedData". */
    private String encryptedDataParameter = WxJsCodeAuthenticationProcessingFilter.SPRING_SECURITY_FORM_ENCRYPTEDDATA_KEY;
    /** the iv parameter name. Defaults to "iv". */
    private String ivParameter = WxJsCodeAuthenticationProcessingFilter.SPRING_SECURITY_FORM_IV_KEY;
    /** the unionid parameter name. Defaults to "unionid". */
    private String unionidParameter = WxJsCodeAuthenticationProcessingFilter.SPRING_SECURITY_FORM_UNIONID_KEY;
    /** the openid parameter name. Defaults to "openid". */
    private String openidParameter = WxJsCodeAuthenticationProcessingFilter.SPRING_SECURITY_FORM_OPENID_KEY;
    /** the username parameter name. Defaults to "username". */
    private String usernameParameter = WxJsCodeAuthenticationProcessingFilter.SPRING_SECURITY_FORM_USERNAME_KEY;
    /** the password parameter name. Defaults to "password". */
    private String passwordParameter = WxJsCodeAuthenticationProcessingFilter.SPRING_SECURITY_FORM_PASSWORD_KEY;
    
	@NestedConfigurationProperty
	private SecurityRedirectProperties redirect = new SecurityRedirectProperties();

	@NestedConfigurationProperty
	private SecurityLogoutProperties logout = new SecurityLogoutProperties();
	
	
}
