package org.springframework.security.boot.weixin.authentication;

import lombok.extern.slf4j.Slf4j;
import me.chanjar.weixin.common.bean.WxOAuth2UserInfo;
import me.chanjar.weixin.common.bean.oauth2.WxOAuth2AccessToken;
import me.chanjar.weixin.common.error.WxErrorException;
import me.chanjar.weixin.mp.api.WxMpService;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Objects;

/**
 * Spring Security {@link AuthenticationProvider} for WeChat Public Account ({@code Mp}) login.
 *
 * <p>Exchanges the supplied OAuth2 authorization {@code code} for an access token
 * via the WeChat {@link WxMpService}, retrieves the user profile and then resolves
 * the local user through the configured {@link UserDetailsServiceAdapter}.</p>
 *
 * <p>Reference:
 * <a href="https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Official_Accounts/official_account_website_authorization.html">
 * official account website authorization</a></p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
@Slf4j
public class WxMpAuthenticationProvider implements AuthenticationProvider {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsServiceAdapter userDetailsService;
    private final WxMpService wxMpService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();

    public WxMpAuthenticationProvider(final WxMpService wxMpService, final UserDetailsServiceAdapter userDetailsService, final PasswordEncoder passwordEncoder) {
        this.wxMpService = wxMpService;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Attempt to authenticate the supplied Public Account authentication token.
     *
     * <p>The resulting {@link Authentication} object is ultimately placed in the
     * security context via
     * {@code SecurityContextHolder.getContext().setAuthentication(authResult)}.</p>
     *
     * @author [@Loong Wan](https://github.com/loong10k)
     * @param authentication the {@link WxMpAuthenticationToken} to authenticate
     * @return the fully populated, authenticated {@link Authentication} object
     * @throws AuthenticationException if authentication fails
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    	Assert.notNull(authentication, "No authentication data provided");

    	if (log.isDebugEnabled()) {
			log.debug("Processing authentication request : " + authentication);
		}

    	WxMpLoginRequest loginRequest = (WxMpLoginRequest) authentication.getPrincipal();


        try {

			WxMpAuthenticationToken loginToken = (WxMpAuthenticationToken) authentication;

			// 表示需要根据code获取会话信息
        	if (StringUtils.hasText(loginRequest.getCode()) ) {
				WxOAuth2AccessToken accessToken = getWxMpService().getOAuth2Service().getAccessToken(loginRequest.getCode());
				if (Objects.nonNull(accessToken)) {
					loginRequest.setAccessToken(accessToken);
					loginRequest.setOpenid(accessToken.getOpenId());
					loginRequest.setUnionid(accessToken.getUnionId());
    			}
     		}

        	if(Objects.isNull(loginRequest.getUserInfo()) && Objects.nonNull(loginRequest.getAccessToken()) ) {
				WxOAuth2UserInfo userInfo = getWxMpService().getOAuth2Service().getUserInfo(loginRequest.getAccessToken(), loginRequest.getLang());
				if (Objects.nonNull(userInfo)) {
					loginRequest.setUserInfo(userInfo);
				}
			}

			UserDetails ud = getUserDetailsService().loadUserDetails(loginToken);

			// User Status Check
		    getUserDetailsChecker().check(ud);

		    WxMaAuthenticationToken authenticationToken = null;
		    if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
		    	authenticationToken = new WxMaAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());
		    } else {
		    	authenticationToken = new WxMaAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
			}
		    authenticationToken.setDetails(authentication.getDetails());

		    return authenticationToken;

		} catch (WxErrorException e) {
			throw new AuthenticationServiceException("微信登录认证失败.", e);
		}

    }

    /**
     * Whether this provider supports the given authentication token type.
     * @param authentication the token class to test
     * @return {@code true} if {@link WxMpAuthenticationToken} is assignable from the given type
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return (WxMpAuthenticationToken.class.isAssignableFrom(authentication));
    }

	/**
	 * Set the checker used to validate the status (e.g. locked, disabled, expired) of
	 * the loaded {@link UserDetails}.
	 * @param userDetailsChecker the checker to use
	 */
	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	/**
	 * Get the underlying {@link WxMpService} used to call WeChat Public Account APIs.
	 * @return the WeChat Public Account service
	 */
	public WxMpService getWxMpService() {
		return wxMpService;
	}

	/**
	 * Get the checker used to validate the loaded {@link UserDetails}.
	 * @return the user details checker
	 */
	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	/**
	 * Get the password encoder used by this provider.
	 * @return the password encoder
	 */
	public PasswordEncoder getPasswordEncoder() {
		return passwordEncoder;
	}

	/**
	 * Get the adapter used to load local user details for the WeChat principal.
	 * @return the user details service adapter
	 */
	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}

}
