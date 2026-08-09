package org.springframework.security.boot;

import cn.binarywang.wx.miniapp.api.WxMaService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.utils.WebSecurityUtils;
import org.springframework.security.boot.weixin.authentication.WxMaAuthenticationProcessingFilter;
import org.springframework.security.boot.weixin.authentication.WxMaAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.CompositeAccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Servlet filter auto-configuration for WeChat Mini Program ({@code Ma}) login.
 *
 * <p>Activated when the {@link WxMaService} class is on the classpath and
 * {@code spring.security.weixin.enabled=true}. It registers the
 * {@link WxMaAuthenticationProvider} and builds a dedicated
 * {@link SecurityFilterChain} that handles POST requests to the configured Mini Program
 * login path (default {@code /login/weixin/ma}).</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@Configuration
@ConditionalOnClass(WxMaService.class)
@ConditionalOnProperty(prefix = SecurityWxProperties.PREFIX, value = "enabled", havingValue = "true")
@AutoConfigureBefore(name = {
	"org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration"
})
/** Configuration for Wx Ma authentication filter chain.
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class SecurityWxMaFilterConfiguration {

	/**
	 * Create the {@link WxMaAuthenticationProvider} that exchanges the Mini Program
	 * {@code jscode} for a session and loads the corresponding user details.
	 * @param wxMaServiceProvider the optional {@link WxMaService} used to call WeChat APIs
	 * @param userDetailsServiceProvider the optional {@link UserDetailsServiceAdapter} used to load local user details
	 * @param passwordEncoderProvider the optional {@link PasswordEncoder} used by the provider
	 * @return a new WeChat Mini Program authentication provider
	 */
	@Bean
	public WxMaAuthenticationProvider wxJsCodeAuthenticationProvider(ObjectProvider<WxMaService> wxMaServiceProvider,
																	 ObjectProvider<UserDetailsServiceAdapter> userDetailsServiceProvider,
																	 ObjectProvider<PasswordEncoder> passwordEncoderProvider) {
		return new WxMaAuthenticationProvider(wxMaServiceProvider.getIfAvailable(), userDetailsServiceProvider.getIfAvailable(), passwordEncoderProvider.getIfAvailable());
	}
   	/** Adapter implementation for Wx Ma Web Security Customizer.
   	 *
   	 * @author [@Loong Wan](https://github.com/loong10k)
   	 * @since 1.0.0
   	 */

    @Configuration
    @EnableConfigurationProperties({ SecurityWxProperties.class, SecurityWxMaAuthcProperties.class, SecurityBizProperties.class })
   	static class WxMaWebSecurityCustomizerAdapter extends WebSecurityCustomizerAdapter {
    	
    	private final SecurityWxMaAuthcProperties authcProperties;

		private final AccessDeniedHandler accessDeniedHandler;
    	private final LocaleContextFilter localeContextFilter;
	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
	    private final ObjectMapper objectMapper;
    	private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
   		
   		public WxMaWebSecurityCustomizerAdapter(
   			
   				SecurityBizProperties bizProperties,
				SecuritySessionMgtProperties sessionMgtProperties,
   				SecurityWxMaAuthcProperties authcProperties,

				ObjectProvider<AccessDeniedHandler> accessDeniedHandlerProvider,
   				ObjectProvider<LocaleContextFilter> localeContextProvider,
				ObjectProvider<AuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
   				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider

			) {
   			
   			super(bizProperties, sessionMgtProperties, authenticationProvider.stream().collect(Collectors.toList()));
   			
   			this.authcProperties = authcProperties;

			this.accessDeniedHandler = new CompositeAccessDeniedHandler(accessDeniedHandlerProvider.stream().collect(Collectors.toList()));
   			this.localeContextFilter = localeContextProvider.getIfAvailable();
   			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
   			this.authenticationEntryPoint = WebSecurityUtils.authenticationEntryPoint(authcProperties, sessionMgtProperties, authenticationEntryPointProvider.stream().collect(Collectors.toList()));
   			this.authenticationSuccessHandler = WebSecurityUtils.authenticationSuccessHandler(authcProperties, sessionMgtProperties, authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
   			this.authenticationFailureHandler = WebSecurityUtils.authenticationFailureHandler(authcProperties, sessionMgtProperties, authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
   		}
   		   		
   	    /**
		 * Build the {@link WxMaAuthenticationProcessingFilter} wired with all configured
		 * success/failure handlers, parameter names and supporting services.
		 * @return the configured Mini Program authentication processing filter
		 * @throws Exception if the underlying {@code AuthenticationManager} cannot be resolved
		 */
   	    public WxMaAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
   	    	
   			WxMaAuthenticationProcessingFilter authenticationFilter = new WxMaAuthenticationProcessingFilter(
   					objectMapper);
   			
   			/**
			 * 
			 */
			PropertyMapper map = PropertyMapper.get();
			
			map.from(getSessionMgtProperties().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(authcProperties.getJscodeParameter()).to(authenticationFilter::setJscodeParameter);
			map.from(authcProperties.getSignatureParameter()).to(authenticationFilter::setSignatureParameter);
			map.from(authcProperties.getRawDataParameter()).to(authenticationFilter::setRawDataParameter);
			map.from(authcProperties.getEncryptedDataParameter()).to(authenticationFilter::setEncryptedDataParameter);
			map.from(authcProperties.getIvParameter()).to(authenticationFilter::setIvParameter);
			map.from(authcProperties.getTokenParameter()).to(authenticationFilter::setTokenParameter);

			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			
   	        return authenticationFilter;
   	    }

   		/**
		 * Configure the security filter chain dedicated to WeChat Mini Program login.
		 * @param http the {@link HttpSecurity} to configure
		 * @return the built {@link SecurityFilterChain}
		 * @throws Exception if an error occurs while configuring the chain
		 */
		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE + 8)
		public SecurityFilterChain wxMaSecurityFilterChain(HttpSecurity http) throws Exception {

			http.securityMatcher(authcProperties.getPathPattern())
					.exceptionHandling(configurer -> {
						configurer.authenticationEntryPoint(authenticationEntryPoint)
								.accessDeniedHandler(accessDeniedHandler)
								.accessDeniedPage(authcProperties.getAccessDeniedUrl());
					});
			http.httpBasic(AbstractHttpConfigurer::disable);
			http.addFilterBefore(localeContextFilter, UsernamePasswordAuthenticationFilter.class)
					.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

			super.configure(http, authcProperties.getCors());
			super.configure(http, authcProperties.getCsrf());
			super.configure(http, authcProperties.getHeaders());
			super.configure(http);

			return http.build();
		}

		@Override
	    /** Customizes the web security configuration.
	     * @param web the web
	     */
	    public void customize(WebSecurity web) {
	    	super.customize(web);
	    }

	}

}
