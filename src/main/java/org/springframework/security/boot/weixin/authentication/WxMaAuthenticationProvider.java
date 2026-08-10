package org.springframework.security.boot.weixin.authentication;


import cn.binarywang.wx.miniapp.api.WxMaService;
import cn.binarywang.wx.miniapp.bean.WxMaJscode2SessionResult;
import cn.binarywang.wx.miniapp.bean.WxMaPhoneNumberInfo;
import cn.binarywang.wx.miniapp.bean.WxMaUserInfo;
import me.chanjar.weixin.common.error.WxErrorException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * Spring Security {@link AuthenticationProvider} for WeChat Mini Program ({@code Ma}) login.
 *
 * <p>Exchanges the supplied {@code jscode} for a session key via the WeChat
 * {@link WxMaService}, optionally decrypts the bound phone number and user info,
 * and then resolves the local user through the configured
 * {@link UserDetailsServiceAdapter}.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class WxMaAuthenticationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsServiceAdapter userDetailsService;
    private final WxMaService wxMaService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
    public WxMaAuthenticationProvider(final WxMaService wxMaService, final UserDetailsServiceAdapter userDetailsService, final PasswordEncoder passwordEncoder) {
        this.wxMaService = wxMaService;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Attempt to authenticate the supplied Mini Program authentication token.
     *
     * <p>The resulting {@link Authentication} object is ultimately placed in the
     * security context via
     * {@code SecurityContextHolder.getContext().setAuthentication(authResult)}.</p>
     *
     * @author <a href="https://github.com/loong10k">Loong Wan</a>
     * @param authentication the {@link WxMaAuthenticationToken} to authenticate
     * @return the fully populated, authenticated {@link Authentication} object
     * @throws AuthenticationException if authentication fails
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
 
    	WxMaLoginRequest loginRequest = (WxMaLoginRequest) authentication.getPrincipal();
        
       
        try {
        	
        	WxMaAuthenticationToken loginToken = (WxMaAuthenticationToken) authentication;

        	// 表示需要根据jscode获取会话信息
        	if (StringUtils.hasText(loginRequest.getJscode()) ) {
        		WxMaJscode2SessionResult sessionResult = getWxMaService().jsCode2SessionInfo(loginRequest.getJscode());
    			if (null != sessionResult) {
					loginRequest.setOpenid(sessionResult.getOpenid());
					loginRequest.setUnionid(sessionResult.getUnionid());
					loginRequest.setSessionKey(sessionResult.getSessionKey());
    			}
     		}
			
			if(StringUtils.hasText(loginRequest.getSessionKey()) && StringUtils.hasText(loginRequest.getEncryptedData()) && StringUtils.hasText(loginRequest.getIv()) ) {
				try {
					// 解密手机号码信息
					WxMaPhoneNumberInfo phoneNumberInfo = getWxMaService().getUserService().getPhoneNoInfo(loginRequest.getSessionKey(), loginRequest.getEncryptedData(), loginRequest.getIv());
					if ( Objects.nonNull(phoneNumberInfo) && StringUtils.hasText(phoneNumberInfo.getPhoneNumber())) {
						loginRequest.setPhoneNumberInfo(phoneNumberInfo);
					}
				} catch (Exception e) {
					logger.error(e.getMessage());
				}
			}
			if(Objects.isNull(loginRequest.getUserInfo()) && StringUtils.hasText(loginRequest.getSessionKey()) && StringUtils.hasText(loginRequest.getEncryptedData()) && StringUtils.hasText(loginRequest.getIv())) {
				try {
					// 解密用户信息
					WxMaUserInfo userInfo = getWxMaService().getUserService().getUserInfo(loginRequest.getSessionKey(), loginRequest.getEncryptedData(), loginRequest.getIv() );
					if (Objects.nonNull(userInfo)) {
						loginRequest.setUserInfo(userInfo);
					}
				} catch (Exception e) {
					throw new AuthenticationServiceException("微信登录认证失败.", e);
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
     * @return {@code true} if {@link WxMaAuthenticationToken} is assignable from the given type
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return (WxMaAuthenticationToken.class.isAssignableFrom(authentication));
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
	 * Get the underlying {@link WxMaService} used to call WeChat Mini Program APIs.
	 * @return the WeChat Mini Program service
	 */
	public WxMaService getWxMaService() {
		return wxMaService;
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
