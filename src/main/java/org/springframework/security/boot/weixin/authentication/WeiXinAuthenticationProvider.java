package org.springframework.security.boot.weixin.authentication;

import java.util.Objects;

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
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import cn.binarywang.wx.miniapp.api.WxMaUserService;
import cn.binarywang.wx.miniapp.bean.WxMaJscode2SessionResult;
import cn.binarywang.wx.miniapp.bean.WxMaPhoneNumberInfo;
import cn.binarywang.wx.miniapp.bean.WxMaUserInfo;
import me.chanjar.weixin.common.error.WxErrorException;

public class WeiXinAuthenticationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsServiceAdapter userDetailsService;
    private final WxMaUserService wxMaUserService;
    private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    
    public WeiXinAuthenticationProvider(final WxMaUserService wxMaUserService, final UserDetailsServiceAdapter userDetailsService, final PasswordEncoder passwordEncoder) {
        this.wxMaUserService = wxMaUserService;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * 
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author 		：<a href="https://github.com/hiwepy">wandl</a>
     * @param authentication  {@link WeiXinAuthenticationToken IdentityCodeAuthenticationToken} 对象
     * @return 认证结果{@link Authentication}对象
     * @throws AuthenticationException  认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
 
    	WeiXinLoginRequest request = (WeiXinLoginRequest) authentication.getPrincipal();
        
        if (!StringUtils.hasLength(request.getJscode())) {
			logger.debug("No jscode found in request.");
			throw new BadCredentialsException("No jscode found in request.");
		}

        try {
        	
			// 根据jscode获取会话信息
			WxMaJscode2SessionResult sessionResult = getWxMaUserService().getSessionInfo(request.getJscode());
			if (null == sessionResult) {
				 
			}
			
			WeiXinAuthenticationToken weixinToken = (WeiXinAuthenticationToken) authentication;
			weixinToken.setOpenid(sessionResult.getOpenid());
			weixinToken.setUnionid(sessionResult.getUnionid());
			weixinToken.setSessionKey(sessionResult.getSessionKey());
			
			try {
				
				UserDetails ud = getUserDetailsService().loadUserDetails(weixinToken);
				
				// 判断是否已经完成绑定
				if (null == ud) {
			    	throw new UsernameNotFoundException(".");
				}
			    
				// User Status Check
			    getUserDetailsChecker().check(ud);
			    
			    WeiXinAuthenticationToken authenticationToken = null;
			    if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
			    	authenticationToken = new WeiXinAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());        	
			    } else {
			    	authenticationToken = new WeiXinAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
				}
			    authenticationToken.setDetails(authentication.getDetails());
			    
			    return authenticationToken;
			    
			} catch (UsernameNotFoundException e) {
				
				// 解密手机号码信息
				WxMaPhoneNumberInfo phoneNumberInfo = getWxMaUserService().getPhoneNoInfo(sessionResult.getSessionKey(), request.getEncryptedData(), request.getIv());
				if ( !Objects.isNull(phoneNumberInfo) && StringUtils.hasText(phoneNumberInfo.getPhoneNumber())) {
					weixinToken.setPhoneNumberInfo(phoneNumberInfo);
			    }
				
			 	// 解密用户信息
				WxMaUserInfo userInfo = getWxMaUserService().getUserInfo(sessionResult.getSessionKey(), request.getEncryptedData(), request.getIv() );
			    if (null == userInfo) {
			    	weixinToken.setUserInfo(userInfo);
			    }
				
			    // 调用保存和返回保存后认证信息接口
			    UserDetails ud = getUserDetailsService().loadUserDetailsWithSave(weixinToken);
			    
			    // User Status Check
			    getUserDetailsChecker().check(ud);
			    
			    WeiXinAuthenticationToken authenticationToken = null;
			    if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
			    	authenticationToken = new WeiXinAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());        	
			    } else {
			    	authenticationToken = new WeiXinAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
				}
			    authenticationToken.setDetails(authentication.getDetails());
			    
			    return authenticationToken;
			}
		} catch (WxErrorException e) {
			throw new AuthenticationServiceException("微信登录认证失败.", e);
		}
       
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (WeiXinAuthenticationToken.class.isAssignableFrom(authentication));
    }

	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public WxMaUserService getWxMaUserService() {
		return wxMaUserService;
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
