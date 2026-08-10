package org.springframework.security.boot.weixin.authentication;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Getter;
import lombok.Setter;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserProfilePayload;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Matched success handler invoked after a WeChat (Public Account or Mini Program)
 * authentication succeeds.
 *
 * <p>Serializes the authenticated profile (optionally as a JWT built through the
 * {@link JwtPayloadRepository}) back to the front end as JSON.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class WxMatchedAuthenticationSuccessHandler implements MatchedAuthenticationSuccessHandler {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	@Setter
    @Getter
    private JwtPayloadRepository payloadRepository;
	@Setter
    @Getter
    private boolean checkExpiry = false;

	/**
	 * Construct a success handler with the optional {@link JwtPayloadRepository} used
	 * to build the JWT payload.
	 * @param payloadRepository the JWT payload repository, may be {@code null}
	 */
	public WxMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		this.setPayloadRepository(payloadRepository);
	}

	/**
	 * Whether this handler supports the given authentication token type.
	 * @param authentication the authentication to test
	 * @return {@code true} if the authentication is a {@link WxMpAuthenticationToken} or a {@link WxMaAuthenticationToken}
	 */
	@Override
	public boolean supports(Authentication authentication) {
		return SubjectUtils.isAssignableFrom(authentication.getClass(), WxMpAuthenticationToken.class, WxMaAuthenticationToken.class);
	}

	/**
	 * Build the success payload (optionally as a JWT) and write it to the response as JSON.
	 * @param request the HTTP request that triggered the authentication
	 * @param response the HTTP response to write to
	 * @param authentication the successful authentication
	 * @throws IOException if writing the response fails
	 * @throws ServletException on generic servlet errors
	 */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
    	
    	// 设置状态码和响应头
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		// 国际化后的异常信息
		String message = messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey());
		// 写出JSON
		UserProfilePayload profilePayload = getPayloadRepository().getProfilePayload((AbstractAuthenticationToken) authentication, isCheckExpiry());
		JSON.writeTo(response.getOutputStream(), AuthResponse.success(message, profilePayload));
		
    }

}
