package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.weixin.authentication.WxJsCodeAuthenticationProcessingFilter;
import org.springframework.security.boot.weixin.authentication.WxJsCodeAuthenticationProvider;
import org.springframework.security.boot.weixin.authentication.WxMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.weixin.authentication.WxMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.weixin.authentication.WxMatchedAuthenticationSuccessHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;

import com.fasterxml.jackson.databind.ObjectMapper;

import cn.binarywang.wx.miniapp.api.WxMaService;

@Configuration
@ConditionalOnClass(WxMaService.class)
@ConditionalOnProperty(prefix = SecurityWxProperties.PREFIX, value = "enabled", havingValue = "true")
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@EnableConfigurationProperties({ SecurityWxProperties.class })
public class SecurityWxJsCodeFilterConfiguration {
    
	@Bean
	public WxJsCodeAuthenticationProvider wxJsCodeAuthenticationProvider(WxMaService wxMaService,
			UserDetailsServiceAdapter userDetailsService, PasswordEncoder passwordEncoder) {
		return new WxJsCodeAuthenticationProvider(wxMaService, userDetailsService, passwordEncoder);
	}
	
    @Configuration
   	@EnableConfigurationProperties({ SecurityWxProperties.class, SecurityBizProperties.class })
    @Order(SecurityProperties.DEFAULT_FILTER_ORDER + 6)
   	static class WxJsCodeWebSecurityConfigurerAdapter extends SecurityBizConfigurerAdapter {
    	
    	private final SecurityWxAuthcProperties authcProperties;
    	
	    private final AuthenticationEntryPoint authenticationEntryPoint;
  	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
  	    private final AuthenticationFailureHandler authenticationFailureHandler;
  	    private final ObjectMapper objectMapper;
      	private final RequestCache requestCache;
      	private final RememberMeServices rememberMeServices;
  		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
   		
   		public WxJsCodeWebSecurityConfigurerAdapter(
   			
   				SecurityBizProperties bizProperties,
   				SecurityWxAuthcProperties authcProperties,

   				ObjectProvider<WxJsCodeAuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<WxMatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<WxMatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
   				ObjectProvider<WxMatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				ObjectProvider<LogoutHandler> logoutHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider

			) {
   			
   			super(bizProperties, authcProperties, authenticationProvider.stream().collect(Collectors.toList()),
					authenticationManagerProvider.getIfAvailable());
   			
   			this.authcProperties = authcProperties;
   			
   			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
   			this.authenticationEntryPoint = super.authenticationEntryPoint(authenticationEntryPointProvider.stream().collect(Collectors.toList()));
   			this.authenticationSuccessHandler = super.authenticationSuccessHandler(authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
   			this.authenticationFailureHandler = super.authenticationFailureHandler(authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.requestCache = super.requestCache();
   			this.rememberMeServices = super.rememberMeServices();
   			this.sessionAuthenticationStrategy = super.sessionAuthenticationStrategy();
   			
   		}
   		   		
   	    public WxJsCodeAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
   	    	
   			WxJsCodeAuthenticationProcessingFilter authenticationFilter = new WxJsCodeAuthenticationProcessingFilter(
   					objectMapper);
   			
   			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(authcProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(authcProperties.getJscodeParameter()).to(authenticationFilter::setJscodeParameter);
			map.from(authcProperties.getSignatureParameter()).to(authenticationFilter::setSignatureParameter);
			map.from(authcProperties.getRawDataParameter()).to(authenticationFilter::setRawDataParameter);
			map.from(authcProperties.getEncryptedDataParameter()).to(authenticationFilter::setEncryptedDataParameter);
			map.from(authcProperties.getIvParameter()).to(authenticationFilter::setIvParameter);
			map.from(authcProperties.getUsernameParameter()).to(authenticationFilter::setUsernameParameter);
			map.from(authcProperties.getPasswordParameter()).to(authenticationFilter::setPasswordParameter);
			
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			
   	        return authenticationFilter;
   	    }

   	    @Override
		public void configure(HttpSecurity http) throws Exception {
			
		    // Session 管理器配置
	    	http.requestCache()
	        	.requestCache(requestCache)
	        	// 异常处理
	        	.and()
	        	.exceptionHandling()
	        	.authenticationEntryPoint(authenticationEntryPoint)
	        	.and()
	        	.httpBasic()
	        	.authenticationEntryPoint(authenticationEntryPoint)
	        	.and()
	        	.antMatcher(authcProperties.getPathPattern())
	        	.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class); 

	    	super.configure(http, authcProperties.getCors());
	    	super.configure(http, authcProperties.getCsrf());
	    	super.configure(http, authcProperties.getHeaders());
	    	super.configure(http);
	    	
		}
		
		@Override
	    public void configure(WebSecurity web) throws Exception {
	    	super.configure(web);
	    }

   	}

}
