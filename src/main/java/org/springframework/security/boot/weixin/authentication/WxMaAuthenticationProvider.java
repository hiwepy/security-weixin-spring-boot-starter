package org.springframework.security.boot.weixin.authentication;

import java.util.Objects;

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

import cn.binarywang.wx.miniapp.api.WxMaService;
import cn.binarywang.wx.miniapp.bean.WxMaJscode2SessionResult;
import cn.binarywang.wx.miniapp.bean.WxMaPhoneNumberInfo;
import cn.binarywang.wx.miniapp.bean.WxMaUserInfo;
import me.chanjar.weixin.common.error.WxErrorException;

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

    @Override
    public boolean supports(Class<?> authentication) {
        return (WxMaAuthenticationToken.class.isAssignableFrom(authentication));
    }

	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public WxMaService getWxMaService() {
		return wxMaService;
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
