package org.springframework.security.boot;

import com.fasterxml.jackson.databind.ObjectMapper;
import me.chanjar.weixin.mp.api.WxMpService;
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
import org.springframework.security.boot.weixin.authentication.WxMpAuthenticationProcessingFilter;
import org.springframework.security.boot.weixin.authentication.WxMpAuthenticationProvider;
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
 * Servlet filter auto-configuration for WeChat Public Account ({@code Mp}) login.
 *
 * <p>Activated when the {@link WxMpService} class is on the classpath and
 * {@code spring.security.weixin.enabled=true}. It registers the
 * {@link WxMpAuthenticationProvider} and builds a dedicated
 * {@link SecurityFilterChain} that handles POST requests to the configured Public
 * Account login path (default {@code /login/weixin/mp}).</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@Configuration
@ConditionalOnClass(WxMpService.class)
@ConditionalOnProperty(prefix = SecurityWxProperties.PREFIX, value = "enabled", havingValue = "true")
@AutoConfigureBefore(name = {
	"org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration"
})
public class SecurityWxMpFilterConfiguration {

	/**
	 * Create the {@link WxMpAuthenticationProvider} that exchanges the OAuth2
	 * {@code code} for an access token and loads the corresponding user details.
	 * @param wxMpServicerovider the optional {@link WxMpService} used to call WeChat APIs
	 * @param userDetailsServiceProvider the optional {@link UserDetailsServiceAdapter} used to load local user details
	 * @param passwordEncoderProvider the optional {@link PasswordEncoder} used by the provider
	 * @return a new WeChat Public Account authentication provider
	 */
	@Bean
	public WxMpAuthenticationProvider wxMpAuthenticationProvider(ObjectProvider<WxMpService> wxMpServicerovider,
																	 ObjectProvider<UserDetailsServiceAdapter> userDetailsServiceProvider,
																	 ObjectProvider<PasswordEncoder> passwordEncoderProvider) {
		return new WxMpAuthenticationProvider(wxMpServicerovider.getIfAvailable(), userDetailsServiceProvider.getIfAvailable(), passwordEncoderProvider.getIfAvailable());
	}
	
    @Configuration
   	@EnableConfigurationProperties({ SecurityWxProperties.class, SecurityWxMpAuthcProperties.class, SecurityBizProperties.class })
    static class WxMpWebSecurityCustomizerAdapter extends WebSecurityCustomizerAdapter {
    	
    	private final SecurityWxMpAuthcProperties authcProperties;

		private final AccessDeniedHandler accessDeniedHandler;
    	private final LocaleContextFilter localeContextFilter;
	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
	    private final ObjectMapper objectMapper;
    	private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
   		
   		public WxMpWebSecurityCustomizerAdapter(
   			
   				SecurityBizProperties bizProperties,
				SecuritySessionMgtProperties sessionMgtProperties,
   				SecurityWxMpAuthcProperties authcProperties,

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
		 * Build the {@link WxMpAuthenticationProcessingFilter} wired with all configured
		 * success/failure handlers, parameter names and supporting services.
		 * @return the configured Public Account authentication processing filter
		 * @throws Exception if the underlying {@code AuthenticationManager} cannot be resolved
		 */
   	    public WxMpAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
   	    	
   	    	WxMpAuthenticationProcessingFilter authenticationFilter = new WxMpAuthenticationProcessingFilter(
   					objectMapper);
   			
   			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get();
			
			map.from(getSessionMgtProperties().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(authcProperties.getCodeParameter()).to(authenticationFilter::setCodeParameter);
			map.from(authcProperties.getTokenParameter()).to(authenticationFilter::setTokenParameter);
			
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
			
   	        return authenticationFilter;
   	    }

		/**
		 * Configure the security filter chain dedicated to WeChat Public Account login.
		 * @param http the {@link HttpSecurity} to configure
		 * @return the built {@link SecurityFilterChain}
		 * @throws Exception if an error occurs while configuring the chain
		 */
		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE + 7)
		public SecurityFilterChain wxMpSecurityFilterChain(HttpSecurity http) throws Exception {
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
		public void customize(WebSecurity web) {
			super.customize(web);
		}
   	}

}
