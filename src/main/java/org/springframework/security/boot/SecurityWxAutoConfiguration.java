package org.springframework.security.boot;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.weixin.authentication.WxMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.weixin.authentication.WxMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.weixin.authentication.WxMatchedAuthenticationSuccessHandler;

/**
 * Auto-configuration for the WeChat (WeiXin) Spring Security authentication handlers.
 *
 * <p>Registers the matched entry point, failure handler and success handler beans that
 * are shared by both the Mini Program ({@code ma}) and the Public Account ({@code mp})
 * authentication filter chains. The configuration is activated only when
 * {@code spring.security.weixin.enabled} is {@code true}.</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityWxProperties.PREFIX, value = "enabled", havingValue = "true")
public class SecurityWxAutoConfiguration{

	/**
	 * Create the {@link WxMatchedAuthenticationEntryPoint} that renders WeChat
	 * authentication exceptions as JSON responses.
	 * @return a new matched authentication entry point
	 */
	@Bean
	public WxMatchedAuthenticationEntryPoint wxMatchedAuthenticationEntryPoint() {
		return new WxMatchedAuthenticationEntryPoint();
	}

	/**
	 * Create the {@link WxMatchedAuthenticationFailureHandler} that renders WeChat
	 * authentication failure responses as JSON.
	 * @return a new matched authentication failure handler
	 */
	@Bean
	public WxMatchedAuthenticationFailureHandler wxMatchedAuthenticationFailureHandler() {
		return new WxMatchedAuthenticationFailureHandler();
	}

	/**
	 * Create the {@link WxMatchedAuthenticationSuccessHandler} that serializes the
	 * authenticated profile (optionally as a JWT) back to the front end.
	 * @param payloadRepositoryProvider provider for the optional {@link JwtPayloadRepository} used to build the JWT payload
	 * @return a new matched authentication success handler
	 */
	@Bean
	public WxMatchedAuthenticationSuccessHandler wxMatchedAuthenticationSuccessHandler(ObjectProvider<JwtPayloadRepository> payloadRepositoryProvider) {
		return new WxMatchedAuthenticationSuccessHandler(payloadRepositoryProvider.getIfAvailable());
	}

}
