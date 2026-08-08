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

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.boot.weixin.exception.WxJsCodeInvalidException;
import org.springframework.security.core.Authentication;

import java.io.BufferedReader;
import java.io.StringReader;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WxMaAuthenticationProcessingFilter}.
 *
 * @author <a href="https://github.com/loong10k">[@Loong Wan]</a>
 * @since 1.0.0
 */
@DisplayName("WxMaAuthenticationProcessingFilter Tests")
class WxMaAuthenticationProcessingFilterTest {

    private WxMaAuthenticationProcessingFilter filter;

    @BeforeEach
    void setUp() {
        filter = new WxMaAuthenticationProcessingFilter(new ObjectMapper());
    }

    @Test
    @DisplayName("Default parameter names match the public constants")
    void testDefaultParameterNames() {
        assertThat(filter.getJscodeParameter()).isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_JSCODE_KEY);
        assertThat(filter.getSignatureParameter()).isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_SIGNATURE_KEY);
        assertThat(filter.getRawDataParameter()).isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_RAWDATA_KEY);
        assertThat(filter.getEncryptedDataParameter()).isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_ENCRYPTEDDATA_KEY);
        assertThat(filter.getIvParameter()).isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_IV_KEY);
        assertThat(filter.getTokenParameter()).isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_TOKEN_KEY);
    }

    @Test
    @DisplayName("Setters update the parameter names")
    void testParameterSetters() {
        filter.setJscodeParameter("j");
        filter.setSignatureParameter("s");
        filter.setRawDataParameter("r");
        filter.setEncryptedDataParameter("e");
        filter.setIvParameter("i");
        filter.setTokenParameter("t");

        assertThat(filter.getJscodeParameter()).isEqualTo("j");
        assertThat(filter.getSignatureParameter()).isEqualTo("s");
        assertThat(filter.getRawDataParameter()).isEqualTo("r");
        assertThat(filter.getEncryptedDataParameter()).isEqualTo("e");
        assertThat(filter.getIvParameter()).isEqualTo("i");
        assertThat(filter.getTokenParameter()).isEqualTo("t");
    }

    @Test
    @DisplayName("doAttemptAuthentication throws when jscode is missing on a form request")
    void testAttemptFormWithoutJscode() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("jscode")).thenReturn(null);

        assertThatThrownBy(() -> filter.doAttemptAuthentication(request, mock(HttpServletResponse.class)))
                .isInstanceOf(WxJsCodeInvalidException.class);
    }

    @Test
    @DisplayName("doAttemptAuthentication authenticates a populated form request")
    void testAttemptFormSuccess() throws Exception {
        AuthenticationManager manager = mock(AuthenticationManager.class);
        Authentication result = mock(Authentication.class);
        when(manager.authenticate(any())).thenReturn(result);
        filter.setAuthenticationManager(manager);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("jscode")).thenReturn("js");
        when(request.getParameter("sessionKey")).thenReturn("sk");
        when(request.getParameter("unionid")).thenReturn("un");
        when(request.getParameter("openid")).thenReturn("op");
        when(request.getParameter("signature")).thenReturn("sg");
        when(request.getParameter("rawData")).thenReturn("rd");
        when(request.getParameter("encryptedData")).thenReturn("ed");
        when(request.getParameter("iv")).thenReturn("iv");
        when(request.getParameter("token")).thenReturn("tk");

        Authentication auth = filter.doAttemptAuthentication(request, mock(HttpServletResponse.class));
        assertThat(auth).isSameAs(result);
        verify(manager).authenticate(any(WxMaAuthenticationToken.class));
    }

    @Test
    @DisplayName("doAttemptAuthentication authenticates a JSON request")
    void testAttemptJsonSuccess() throws Exception {
        AuthenticationManager manager = mock(AuthenticationManager.class);
        Authentication result = mock(Authentication.class);
        when(manager.authenticate(any())).thenReturn(result);
        filter.setAuthenticationManager(manager);

        String json = "{\"jscode\":\"jc\",\"sessionKey\":\"sk\"}";
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getReader()).thenReturn(new BufferedReader(new StringReader(json)));

        // WebUtils.isObjectRequest requires POST method and Content-Type: application/json
        when(request.getMethod()).thenReturn("POST");
        when(request.getHeader("Content-Type")).thenReturn("application/json");

        Authentication auth = filter.doAttemptAuthentication(request, mock(HttpServletResponse.class));
        assertThat(auth).isSameAs(result);
    }

    @Test
    @DisplayName("doAttemptAuthentication throws when JSON body has no jscode")
    void testAttemptJsonWithoutJscode() throws Exception {
        String json = "{}";
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getReader()).thenReturn(new BufferedReader(new StringReader(json)));
        when(request.getMethod()).thenReturn("POST");
        when(request.getHeader("Content-Type")).thenReturn("application/json");

        assertThatThrownBy(() -> filter.doAttemptAuthentication(request, mock(HttpServletResponse.class)))
                .isInstanceOf(WxJsCodeInvalidException.class);
    }

    @Test
    @DisplayName("doAttemptAuthentication wraps malformed JSON as InternalAuthenticationServiceException")
    void testAttemptMalformedJson() throws Exception {
        String json = "{not json";
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getReader()).thenReturn(new BufferedReader(new StringReader(json)));
        when(request.getMethod()).thenReturn("POST");
        when(request.getHeader("Content-Type")).thenReturn("application/json");

        assertThatThrownBy(() -> filter.doAttemptAuthentication(request, mock(HttpServletResponse.class)))
                .isInstanceOf(InternalAuthenticationServiceException.class);
    }

    @Test
    @DisplayName("doAttemptAuthentication authenticates when form parameters are partially null (defaults to empty)")
    void testAttemptFormWithNullParameters() throws Exception {
        AuthenticationManager manager = mock(AuthenticationManager.class);
        Authentication result = mock(Authentication.class);
        when(manager.authenticate(any())).thenReturn(result);
        filter.setAuthenticationManager(manager);

        HttpServletRequest request = mock(HttpServletRequest.class);
        // jscode present, the rest null to exercise the null-coalescing branches
        when(request.getParameter("jscode")).thenReturn("js");
        when(request.getParameter("sessionKey")).thenReturn(null);
        when(request.getParameter("unionid")).thenReturn(null);
        when(request.getParameter("openid")).thenReturn(null);
        when(request.getParameter("signature")).thenReturn(null);
        when(request.getParameter("rawData")).thenReturn(null);
        when(request.getParameter("encryptedData")).thenReturn(null);
        when(request.getParameter("iv")).thenReturn(null);
        when(request.getParameter("token")).thenReturn(null);

        Authentication auth = filter.doAttemptAuthentication(request, mock(HttpServletResponse.class));
        assertThat(auth).isSameAs(result);
    }

    @Test
    @DisplayName("doAttemptAuthentication wraps a JSON mapping error as InternalAuthenticationServiceException")
    void testAttemptJsonMappingError() throws Exception {
        // A JSON array (not an object) triggers a JsonMappingException when bound to WxMaLoginRequest
        String json = "[]";
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getReader()).thenReturn(new BufferedReader(new StringReader(json)));
        when(request.getMethod()).thenReturn("POST");
        when(request.getHeader("Content-Type")).thenReturn("application/json");

        assertThatThrownBy(() -> filter.doAttemptAuthentication(request, mock(HttpServletResponse.class)))
                .isInstanceOf(InternalAuthenticationServiceException.class);
    }
}
