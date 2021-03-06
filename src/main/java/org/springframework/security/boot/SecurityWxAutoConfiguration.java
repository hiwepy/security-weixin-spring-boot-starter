package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.weixin.authentication.WxMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.weixin.authentication.WxMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.weixin.authentication.WxMatchedAuthenticationSuccessHandler;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityWxProperties.PREFIX, value = "enabled", havingValue = "true")
public class SecurityWxAutoConfiguration{
	
	@Bean
	public WxMatchedAuthenticationEntryPoint wxMatchedAuthenticationEntryPoint() {
		return new WxMatchedAuthenticationEntryPoint();
	}
	
	@Bean
	public WxMatchedAuthenticationFailureHandler wxMatchedAuthenticationFailureHandler() {
		return new WxMatchedAuthenticationFailureHandler();
	}
	
	@Bean
	public WxMatchedAuthenticationSuccessHandler wxMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new WxMatchedAuthenticationSuccessHandler(payloadRepository);
	}
	
}
