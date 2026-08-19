/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.weixin.authentication;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.PostOnlyAuthenticationProcessingFilter;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.io.IOException;

/**
 * Authentication processing filter for WeChat Public Account ({@code Mp}) login.
 *
 * <p>Intercepts POST requests to {@code /login/weixin/mp} (by default) and builds an
 * {@link WxMpAuthenticationToken} from either a JSON request body or form parameters,
 * extracting the OAuth2 authorization {@code code}, {@code state} and {@code token}
 * fields.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class WxMpAuthenticationProcessingFilter extends PostOnlyAuthenticationProcessingFilter {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	
	/**
	 * Constructs a new wx mp authentication processing filter instance.
	 *
	 * @param objectMapper the object mapper
	 */
	public static final String SPRING_SECURITY_FORM_CODE_KEY = "code";
	/**
	 * Constructs a new wx mp authentication processing filter instance.
	 *
	 * @param objectMapper the object mapper
	 */
	public static final String SPRING_SECURITY_FORM_STATE_KEY = "state";
	/**
	 * Constructs a new wx mp authentication processing filter instance.
	 *
	 * @param objectMapper the object mapper
	 */
	public static final String SPRING_SECURITY_FORM_TOKEN_KEY = "token";

    @Setter
    private String codeParameter = SPRING_SECURITY_FORM_CODE_KEY;
	@Setter
    private String stateParameter = SPRING_SECURITY_FORM_STATE_KEY;
	@Setter
    private String tokenParameter = SPRING_SECURITY_FORM_TOKEN_KEY;
	private final ObjectMapper objectMapper;
	
    /**
     * Constructs a new wx mp authentication processing filter instance.
     *
     * @param objectMapper the object mapper
     */
    public WxMpAuthenticationProcessingFilter(ObjectMapper objectMapper) {
		super(PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/login/weixin/mp"));
		this.objectMapper = objectMapper;
    }

    /**
     * Attempt to authenticate the WeChat Public Account login request by extracting
     * the login parameters and submitting an {@link WxMpAuthenticationToken} to the
     * authentication manager.
     * @param request the HTTP request carrying the login data
     * @param response the HTTP response
     * @return the fully populated, authenticated {@link Authentication} object
     * @throws AuthenticationException if authentication fails
     * @throws IOException if reading the request body fails
     * @throws ServletException on generic servlet errors
     */
    @Override
    public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        
        try {

			AbstractAuthenticationToken authRequest = null;
			
			// Post && JSON
			if(WebUtils.isObjectRequest(request)) {
				
				WxMpLoginRequest loginRequest = objectMapper.readValue(request.getReader(), WxMpLoginRequest.class);
		 		authRequest = this.authenticationToken( loginRequest );
		 		
			} else {
				
				String code = obtainCode(request);
				String state = obtainState(request);
				String token = obtainToken(request);

		        if (code == null) {
		        	code = "";
		        }
		        if (state == null) {
		        	state = "";
		        }
		        if (token == null) {
					token = "";
		        }

		 		authRequest = this.authenticationToken( new WxMpLoginRequest(code, state, token) );
		 		
			}

			// Allow subclasses to set the "details" property
			setDetails(request, authRequest);

			return this.getAuthenticationManager().authenticate(authRequest);

		} catch (JsonParseException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		} catch (JsonMappingException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		} catch (IOException e) {
			throw new InternalAuthenticationServiceException(e.getMessage());
		}

    }

    /**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	@Override
	protected void setDetails(HttpServletRequest request,
							  AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	/**
	 * Build an unauthenticated {@link WxMpAuthenticationToken} from the given login
	 * request.
	 * @param loginRequest the Public Account login request carrying the OAuth2 parameters
	 * @return an unauthenticated authentication token
	 */
	protected AbstractAuthenticationToken authenticationToken(WxMpLoginRequest loginRequest) {
		return new WxMpAuthenticationToken( loginRequest, Boolean.TRUE.toString() );
	}

	/**
	 * Obtain the OAuth2 authorization {@code code} parameter value from the request.
	 * @param request the HTTP request
	 * @return the code value, or {@code null} if absent
	 */
	protected String obtainCode(HttpServletRequest request) {
        return request.getParameter(codeParameter);
    }

	/**
	 * Obtain the OAuth2 {@code state} parameter value from the request.
	 * @param request the HTTP request
	 * @return the state value, or {@code null} if absent
	 */
	protected String obtainState(HttpServletRequest request) {
        return request.getParameter(stateParameter);
    }

	/**
	 * Obtain the {@code token} parameter value used to bind the WeChat user to a local account.
	 * @param request the HTTP request
	 * @return the token value, or {@code null} if absent
	 */
	protected String obtainToken(HttpServletRequest request) {
		return request.getParameter(tokenParameter);
	}

}
