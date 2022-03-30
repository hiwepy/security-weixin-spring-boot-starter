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

public class WxMaAuthenticationProcessingFilter extends PostOnlyAuthenticationProcessingFilter {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	public static final String SPRING_SECURITY_FORM_JSCODE_KEY = "jscode";
	public static final String SPRING_SECURITY_FORM_SESSIONKEY_KEY = "sessionKey";
	public static final String SPRING_SECURITY_FORM_UNIONID_KEY = "unionid";
	public static final String SPRING_SECURITY_FORM_OPENID_KEY = "openid";
    public static final String SPRING_SECURITY_FORM_SIGNATURE_KEY = "signature";
    public static final String SPRING_SECURITY_FORM_RAWDATA_KEY = "rawData";
    public static final String SPRING_SECURITY_FORM_ENCRYPTEDDATA_KEY = "encryptedData";
    public static final String SPRING_SECURITY_FORM_IV_KEY = "iv";
    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";

    private String jscodeParameter = SPRING_SECURITY_FORM_JSCODE_KEY;
    private String sessionKeyParameter = SPRING_SECURITY_FORM_SESSIONKEY_KEY;
    private String unionidParameter = SPRING_SECURITY_FORM_UNIONID_KEY;
    private String openidParameter = SPRING_SECURITY_FORM_OPENID_KEY;
    private String signatureParameter = SPRING_SECURITY_FORM_SIGNATURE_KEY;
    private String rawDataParameter = SPRING_SECURITY_FORM_RAWDATA_KEY;
    private String encryptedDataParameter = SPRING_SECURITY_FORM_ENCRYPTEDDATA_KEY;
    private String ivParameter = SPRING_SECURITY_FORM_IV_KEY;
    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
    private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;

	private final ObjectMapper objectMapper;

    public WxMaAuthenticationProcessingFilter(ObjectMapper objectMapper) {
    	super(new AntPathRequestMatcher("/login/weixin/ma"));
		this.objectMapper = objectMapper;
    }

    @Override
    public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        try {

			AbstractAuthenticationToken authRequest = null;
			// Post && JSON
			if(WebUtils.isObjectRequest(request)) {

				WxMaLoginRequest loginRequest = objectMapper.readValue(request.getReader(), WxMaLoginRequest.class);
		 		authRequest = this.authenticationToken( loginRequest );

			} else {

		        String jscode = obtainJscode(request);
		        String sessionKey = obtainSessionKey(request);
		        String unionid = obtainUnionid(request);
		        String openid = obtainOpenid(request);
		        String signature = obtainSignature(request);
		        String rawData = obtainRawData(request);
		        String encryptedData = obtainEncryptedData(request);
		        String iv = obtainIv(request);
		        String username = obtainUsername(request);
		        String password = obtainPassword(request);

		        if (jscode == null) {
		        	jscode = "";
		        }
		        if (sessionKey == null) {
		        	sessionKey = "";
		        }
		        if (unionid == null) {
		        	unionid = "";
		        }
		        if (openid == null) {
		        	openid = "";
		        }
		        if (signature == null) {
		        	signature = "";
		        }
		        if (rawData == null) {
		        	rawData = "";
		        }
		        if (encryptedData == null) {
		        	encryptedData = "";
		        }
		        if (iv == null) {
		        	iv = "";
		        }
		        if (username == null) {
		        	username = "";
		        }
		        if (password == null) {
		        	password = "";
		        }
		 		authRequest = this.authenticationToken( new WxMaLoginRequest(jscode, sessionKey, unionid, openid,
		 				signature, rawData, encryptedData, iv, username, password, null));

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

	protected AbstractAuthenticationToken authenticationToken(WxMaLoginRequest loginRequest) {
		return new WxMaAuthenticationToken( loginRequest, Boolean.TRUE.toString() );
	}

	protected String obtainJscode(HttpServletRequest request) {
        return request.getParameter(jscodeParameter);
    }

	protected String obtainSessionKey(HttpServletRequest request) {
        return request.getParameter(sessionKeyParameter);
    }

	protected String obtainUnionid(HttpServletRequest request) {
        return request.getParameter(unionidParameter);
    }

	protected String obtainOpenid(HttpServletRequest request) {
        return request.getParameter(openidParameter);
    }


	protected String obtainSignature(HttpServletRequest request) {
        return request.getParameter(signatureParameter);
    }

	protected String obtainRawData(HttpServletRequest request) {
        return request.getParameter(rawDataParameter);
    }

	protected String obtainEncryptedData(HttpServletRequest request) {
        return request.getParameter(encryptedDataParameter);
    }

    protected String obtainIv(HttpServletRequest request) {
        return request.getParameter(ivParameter);
    }

    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter(usernameParameter);
    }

    protected String obtainPassword(HttpServletRequest request) {
        return request.getParameter(passwordParameter);
    }

	public String getJscodeParameter() {
		return jscodeParameter;
	}

	public void setJscodeParameter(String jscodeParameter) {
		this.jscodeParameter = jscodeParameter;
	}

	public String getSignatureParameter() {
		return signatureParameter;
	}

	public void setSignatureParameter(String signatureParameter) {
		this.signatureParameter = signatureParameter;
	}

	public String getRawDataParameter() {
		return rawDataParameter;
	}

	public void setRawDataParameter(String rawDataParameter) {
		this.rawDataParameter = rawDataParameter;
	}

	public String getEncryptedDataParameter() {
		return encryptedDataParameter;
	}

	public void setEncryptedDataParameter(String encryptedDataParameter) {
		this.encryptedDataParameter = encryptedDataParameter;
	}

	public String getIvParameter() {
		return ivParameter;
	}

	public void setIvParameter(String ivParameter) {
		this.ivParameter = ivParameter;
	}

	public String getUsernameParameter() {
		return usernameParameter;
	}

	public void setUsernameParameter(String usernameParameter) {
		this.usernameParameter = usernameParameter;
	}

	public String getPasswordParameter() {
		return passwordParameter;
	}

	public void setPasswordParameter(String passwordParameter) {
		this.passwordParameter = passwordParameter;
	}

}
