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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.PostOnlyAuthenticationProcessingFilter;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class WxMpAuthenticationProcessingFilter extends PostOnlyAuthenticationProcessingFilter {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	
	public static final String SPRING_SECURITY_FORM_CODE_KEY = "code";
	public static final String SPRING_SECURITY_FORM_STATE_KEY = "state";
	public static final String SPRING_SECURITY_FORM_TOKEN_KEY = "token";

    private String codeParameter = SPRING_SECURITY_FORM_CODE_KEY;
    private String stateParameter = SPRING_SECURITY_FORM_STATE_KEY;
	private String tokenParameter = SPRING_SECURITY_FORM_TOKEN_KEY;
	private final ObjectMapper objectMapper;
	
    public WxMpAuthenticationProcessingFilter(ObjectMapper objectMapper) {
    	super(new AntPathRequestMatcher("/login/weixin/mp"));
		this.objectMapper = objectMapper;
    }

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
	
	protected AbstractAuthenticationToken authenticationToken(WxMpLoginRequest loginRequest) {
		return new WxMpAuthenticationToken( loginRequest, Boolean.TRUE.toString() );
	}
    
	protected String obtainCode(HttpServletRequest request) {
        return request.getParameter(codeParameter);
    }
	
	protected String obtainState(HttpServletRequest request) {
        return request.getParameter(stateParameter);
    }

	protected String obtainToken(HttpServletRequest request) {
		return request.getParameter(tokenParameter);
	}

	public String getCodeParameter() {
		return codeParameter;
	}

	public void setCodeParameter(String codeParameter) {
		this.codeParameter = codeParameter;
	}

	public void setTokenParameter(String tokenParameter) {
		this.tokenParameter = tokenParameter;
	}

	public String getTokenParameter() {
		return tokenParameter;
	}

}