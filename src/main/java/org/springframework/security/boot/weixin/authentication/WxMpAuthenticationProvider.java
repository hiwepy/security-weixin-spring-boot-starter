package org.springframework.security.boot.weixin.authentication;

import java.util.Objects;

import me.chanjar.weixin.common.bean.WxOAuth2UserInfo;
import me.chanjar.weixin.common.bean.oauth2.WxOAuth2AccessToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
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

import me.chanjar.weixin.common.error.WxErrorException;
import me.chanjar.weixin.mp.api.WxMpService;

/**
 * https://developers.weixin.qq.com/doc/oplatform/Third-party_Platforms/Official_Accounts/official_account_website_authorization.html
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class WxMpAuthenticationProvider implements AuthenticationProvider {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
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
     *
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author 		：<a href="https://github.com/hiwepy">wandl</a>
     * @param authentication  {@link WxMaAuthenticationToken IdentityCodeAuthenticationToken} 对象
     * @return 认证结果{@link Authentication}对象
     * @throws AuthenticationException  认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    	Assert.notNull(authentication, "No authentication data provided");

    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}

    	WxMpLoginRequest loginRequest = (WxMpLoginRequest) authentication.getPrincipal();

        if (!StringUtils.hasLength(loginRequest.getOpenid())) {
			logger.debug("No openid found in request.");
			throw new BadCredentialsException("No openid found in request.");
		}

        try {

			WxMpAuthenticationToken loginToken = (WxMpAuthenticationToken) authentication;
			loginToken.setCode(loginRequest.getCode());
    		loginToken.setOpenid(loginRequest.getOpenid());
			loginToken.setUnionid(loginRequest.getUnionid());
			loginToken.setAccessToken(loginRequest.getAccessToken());
			loginToken.setUserInfo(loginRequest.getUserInfo());

			// 表示需要根据code获取会话信息
        	if ( Objects.isNull(loginRequest.getAccessToken()) && StringUtils.hasText(loginRequest.getCode()) ) {
				WxOAuth2AccessToken accessToken = getWxMpService().getOAuth2Service().getAccessToken(loginRequest.getCode());
    			if (null != accessToken) {
    				loginToken.setAccessToken(accessToken);
    			}
     		}

        	if(Objects.isNull(loginRequest.getUserInfo()) && !Objects.isNull(loginRequest.getAccessToken()) ) {
				WxOAuth2UserInfo userInfo = getWxMpService().getOAuth2Service().getUserInfo(loginToken.getAccessToken(), loginRequest.getLang());
				if (null == userInfo) {
					loginToken.setUserInfo(userInfo);
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

    @Override
    public boolean supports(Class<?> authentication) {
        return (WxMpAuthenticationToken.class.isAssignableFrom(authentication));
    }

	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public WxMpService getWxMpService() {
		return wxMpService;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	public PasswordEncoder getPasswordEncoder() {
		return passwordEncoder;
	}

	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}

}
