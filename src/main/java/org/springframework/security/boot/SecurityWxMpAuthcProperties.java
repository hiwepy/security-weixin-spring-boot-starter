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
import org.springframework.security.boot.weixin.authentication.WxMpAuthenticationProcessingFilter;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(SecurityWxMpAuthcProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityWxMpAuthcProperties extends SecurityAuthcProperties {

	public static final String PREFIX = "spring.security.weixin.mp";

	/** 用户授权完成后的重定向链接，无需urlencode, 方法内会进行encode */
	private String redirectURI;
	/** 应用授权作用域，拥有多个作用域用逗号（,）分隔，网页应用目前仅填写snsapi_login即可 */
	private String scope;
	/** 非必填，用于保持请求和回调的状态，授权请求后原样带回给第三方。该参数可用于防止csrf攻击（跨站请求伪造攻击），建议第三方带上该参数，可设置为简单的随机数加session进行校验 */
	private String state;
	/** the unionid parameter name. Defaults to "unionid". */
	private String unionidParameter = WxMpAuthenticationProcessingFilter.SPRING_SECURITY_FORM_UNIONID_KEY;
	/** the openid parameter name. Defaults to "openid". */
	private String openidParameter = WxMpAuthenticationProcessingFilter.SPRING_SECURITY_FORM_OPENID_KEY;

	@NestedConfigurationProperty
	private SecurityRedirectProperties redirect = new SecurityRedirectProperties();

	@NestedConfigurationProperty
	private SecurityLogoutProperties logout = new SecurityLogoutProperties();

}
