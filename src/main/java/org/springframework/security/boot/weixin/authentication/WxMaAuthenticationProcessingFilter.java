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
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.PostOnlyAuthenticationProcessingFilter;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.boot.weixin.exception.WxJsCodeInvalidException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.util.StringUtils;

import java.io.IOException;

/**
 * Authentication processing filter for WeChat Mini Program ({@code Ma}) login.
 *
 * <p>Intercepts POST requests to {@code /login/weixin/ma} (by default) and builds an
 * {@link WxMaAuthenticationToken} from either a JSON request body or form parameters,
 * extracting the {@code jscode}, {@code sessionKey}, {@code unionid}, {@code openid},
 * {@code signature}, {@code rawData}, {@code encryptedData}, {@code iv} and
 * {@code token} fields.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Slf4j
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
	public static final String SPRING_SECURITY_FORM_TOKEN_KEY = "token";

    private String jscodeParameter = SPRING_SECURITY_FORM_JSCODE_KEY;
    private String sessionKeyParameter = SPRING_SECURITY_FORM_SESSIONKEY_KEY;
    private String unionidParameter = SPRING_SECURITY_FORM_UNIONID_KEY;
    private String openidParameter = SPRING_SECURITY_FORM_OPENID_KEY;
    private String signatureParameter = SPRING_SECURITY_FORM_SIGNATURE_KEY;
    private String rawDataParameter = SPRING_SECURITY_FORM_RAWDATA_KEY;
    private String encryptedDataParameter = SPRING_SECURITY_FORM_ENCRYPTEDDATA_KEY;
    private String ivParameter = SPRING_SECURITY_FORM_IV_KEY;
	private String tokenParameter = SPRING_SECURITY_FORM_TOKEN_KEY;

	private final ObjectMapper objectMapper;

    public WxMaAuthenticationProcessingFilter(ObjectMapper objectMapper) {
		super(PathPatternRequestMatcher.pathPattern(HttpMethod.POST, "/login/weixin/ma"));
		this.objectMapper = objectMapper;
    }

    /**
     * Attempt to authenticate the WeChat Mini Program login request by extracting the
     * login parameters and submitting an {@link WxMaAuthenticationToken} to the
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

				WxMaLoginRequest loginRequest = objectMapper.readValue(request.getReader(), WxMaLoginRequest.class);
				if ( !StringUtils.hasText(loginRequest.getJscode())) {
					log.debug("No jscode found in request.");
					throw new WxJsCodeInvalidException("No jscode found in request.");
				}
		 		authRequest = this.authenticationToken( loginRequest );

			} else {

		        String jscode = obtainJscode(request);
				if ( !StringUtils.hasText(jscode)) {
					log.debug("No jscode found in request.");
					throw new WxJsCodeInvalidException("No jscode found in request.");
				}

		        String sessionKey = obtainSessionKey(request);
		        String unionid = obtainUnionid(request);
		        String openid = obtainOpenid(request);
		        String signature = obtainSignature(request);
		        String rawData = obtainRawData(request);
		        String encryptedData = obtainEncryptedData(request);
		        String iv = obtainIv(request);
				String token = obtainToken(request);

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
		        if (token == null) {
					token = "";
		        }

		 		authRequest = this.authenticationToken( new WxMaLoginRequest(jscode, sessionKey, unionid, openid,
		 				signature, rawData, encryptedData, iv, token));

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
	 * Build an unauthenticated {@link WxMaAuthenticationToken} from the given login
	 * request.
	 * @param loginRequest the Mini Program login request carrying the WeChat parameters
	 * @return an unauthenticated authentication token
	 */
	protected AbstractAuthenticationToken authenticationToken(WxMaLoginRequest loginRequest) {
		return new WxMaAuthenticationToken( loginRequest, Boolean.TRUE.toString() );
	}

	/**
	 * Obtain the {@code jscode} parameter value from the request.
	 * @param request the HTTP request
	 * @return the jscode value, or {@code null} if absent
	 */
	protected String obtainJscode(HttpServletRequest request) {
        return request.getParameter(jscodeParameter);
    }

	/**
	 * Obtain the {@code sessionKey} parameter value from the request.
	 * @param request the HTTP request
	 * @return the session key value, or {@code null} if absent
	 */
	protected String obtainSessionKey(HttpServletRequest request) {
        return request.getParameter(sessionKeyParameter);
    }

	/**
	 * Obtain the {@code unionid} parameter value from the request.
	 * @param request the HTTP request
	 * @return the union id value, or {@code null} if absent
	 */
	protected String obtainUnionid(HttpServletRequest request) {
        return request.getParameter(unionidParameter);
    }

	/**
	 * Obtain the {@code openid} parameter value from the request.
	 * @param request the HTTP request
	 * @return the open id value, or {@code null} if absent
	 */
	protected String obtainOpenid(HttpServletRequest request) {
        return request.getParameter(openidParameter);
    }


	/**
	 * Obtain the {@code signature} parameter value from the request.
	 * @param request the HTTP request
	 * @return the signature value, or {@code null} if absent
	 */
	protected String obtainSignature(HttpServletRequest request) {
        return request.getParameter(signatureParameter);
    }

	/**
	 * Obtain the {@code rawData} parameter value from the request.
	 * @param request the HTTP request
	 * @return the raw data value, or {@code null} if absent
	 */
	protected String obtainRawData(HttpServletRequest request) {
        return request.getParameter(rawDataParameter);
    }

	/**
	 * Obtain the {@code encryptedData} parameter value from the request.
	 * @param request the HTTP request
	 * @return the encrypted data value, or {@code null} if absent
	 */
	protected String obtainEncryptedData(HttpServletRequest request) {
        return request.getParameter(encryptedDataParameter);
    }

	/**
	 * Obtain the {@code iv} (initialization vector) parameter value from the request.
	 * @param request the HTTP request
	 * @return the initialization vector value, or {@code null} if absent
	 */
    protected String obtainIv(HttpServletRequest request) {
        return request.getParameter(ivParameter);
    }

	/**
	 * Obtain the {@code token} parameter value used to bind the WeChat user to a local account.
	 * @param request the HTTP request
	 * @return the token value, or {@code null} if absent
	 */
	protected String obtainToken(HttpServletRequest request) {
		return request.getParameter(tokenParameter);
	}

	/**
	 * Get the configured request parameter name for the {@code jscode}.
	 * @return the jscode parameter name
	 */
	public String getJscodeParameter() {
		return jscodeParameter;
	}

	/**
	 * Set the request parameter name used to read the {@code jscode}.
	 * @param jscodeParameter the jscode parameter name
	 */
	public void setJscodeParameter(String jscodeParameter) {
		this.jscodeParameter = jscodeParameter;
	}

	/**
	 * Get the configured request parameter name for the {@code signature}.
	 * @return the signature parameter name
	 */
	public String getSignatureParameter() {
		return signatureParameter;
	}

	/**
	 * Set the request parameter name used to read the {@code signature}.
	 * @param signatureParameter the signature parameter name
	 */
	public void setSignatureParameter(String signatureParameter) {
		this.signatureParameter = signatureParameter;
	}

	/**
	 * Get the configured request parameter name for the {@code rawData}.
	 * @return the raw data parameter name
	 */
	public String getRawDataParameter() {
		return rawDataParameter;
	}

	/**
	 * Set the request parameter name used to read the {@code rawData}.
	 * @param rawDataParameter the raw data parameter name
	 */
	public void setRawDataParameter(String rawDataParameter) {
		this.rawDataParameter = rawDataParameter;
	}

	/**
	 * Get the configured request parameter name for the {@code encryptedData}.
	 * @return the encrypted data parameter name
	 */
	public String getEncryptedDataParameter() {
		return encryptedDataParameter;
	}

	/**
	 * Set the request parameter name used to read the {@code encryptedData}.
	 * @param encryptedDataParameter the encrypted data parameter name
	 */
	public void setEncryptedDataParameter(String encryptedDataParameter) {
		this.encryptedDataParameter = encryptedDataParameter;
	}

	/**
	 * Get the configured request parameter name for the {@code iv}.
	 * @return the iv parameter name
	 */
	public String getIvParameter() {
		return ivParameter;
	}

	/**
	 * Set the request parameter name used to read the {@code iv}.
	 * @param ivParameter the iv parameter name
	 */
	public void setIvParameter(String ivParameter) {
		this.ivParameter = ivParameter;
	}

	/**
	 * Set the request parameter name used to read the {@code token}.
	 * @param tokenParameter the token parameter name
	 */
	public void setTokenParameter(String tokenParameter) {
		this.tokenParameter = tokenParameter;
	}

	/**
	 * Get the configured request parameter name for the {@code token}.
	 * @return the token parameter name
	 */
	public String getTokenParameter() {
		return tokenParameter;
	}

}
