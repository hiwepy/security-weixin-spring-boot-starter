package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.sms.authentication.WeiXinAuthenticationProvider;
import org.springframework.security.boot.sms.authentication.WeiXinMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.sms.authentication.WeiXinMatchedAuthenticationFailureHandler;
import org.springframework.security.crypto.password.PasswordEncoder;

import cn.binarywang.wx.miniapp.api.WxMaUserService;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityWeiXinProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityWeiXinProperties.class })
public class SecurityWeiXinAutoConfiguration{
	
	@Bean
	public WeiXinMatchedAuthenticationEntryPoint weixinMatchedAuthenticationEntryPoint() {
		return new WeiXinMatchedAuthenticationEntryPoint();
	}
	
	@Bean
	public WeiXinMatchedAuthenticationFailureHandler weixinMatchedAuthenticationFailureHandler() {
		return new WeiXinMatchedAuthenticationFailureHandler();
	}
	
	@Bean
	public WeiXinAuthenticationProvider weixinAuthenticationProvider(WxMaUserService wxMaUserService,
			UserDetailsServiceAdapter userDetailsService, PasswordEncoder passwordEncoder) {
		return new WeiXinAuthenticationProvider(wxMaUserService, userDetailsService, passwordEncoder);
	}
	
}
