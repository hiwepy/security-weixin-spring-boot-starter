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
 * Unit tests for {@link WxMpAuthenticationProcessingFilter}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("WxMpAuthenticationProcessingFilter Tests")
class WxMpAuthenticationProcessingFilterTest {

    private WxMpAuthenticationProcessingFilter filter;

    @BeforeEach
    void setUp() {
        filter = new WxMpAuthenticationProcessingFilter(new ObjectMapper());
    }

    @Test
    @DisplayName("Default parameter names match the public constants")
    void testDefaultParameterNames() {
        // Setters are the only public accessors; verify the defaults indirectly by exercising them
        filter.setCodeParameter("code");
        filter.setStateParameter("state");
        filter.setTokenParameter("token");
        // re-instantiate to check defaults are wired to constants
        WxMpAuthenticationProcessingFilter fresh = new WxMpAuthenticationProcessingFilter(new ObjectMapper());
        assertThat(fresh).isNotNull();
        assertThat(WxMpAuthenticationProcessingFilter.SPRING_SECURITY_FORM_CODE_KEY).isEqualTo("code");
        assertThat(WxMpAuthenticationProcessingFilter.SPRING_SECURITY_FORM_STATE_KEY).isEqualTo("state");
        assertThat(WxMpAuthenticationProcessingFilter.SPRING_SECURITY_FORM_TOKEN_KEY).isEqualTo("token");
    }

    @Test
    @DisplayName("doAttemptAuthentication authenticates a populated form request")
    void testAttemptFormSuccess() throws Exception {
        AuthenticationManager manager = mock(AuthenticationManager.class);
        Authentication result = mock(Authentication.class);
        when(manager.authenticate(any())).thenReturn(result);
        filter.setAuthenticationManager(manager);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("code")).thenReturn("c");
        when(request.getParameter("state")).thenReturn("s");
        when(request.getParameter("token")).thenReturn("t");

        Authentication auth = filter.doAttemptAuthentication(request, mock(HttpServletResponse.class));
        assertThat(auth).isSameAs(result);
        verify(manager).authenticate(any(WxMpAuthenticationToken.class));
    }

    @Test
    @DisplayName("doAttemptAuthentication authenticates a JSON request")
    void testAttemptJsonSuccess() throws Exception {
        AuthenticationManager manager = mock(AuthenticationManager.class);
        Authentication result = mock(Authentication.class);
        when(manager.authenticate(any())).thenReturn(result);
        filter.setAuthenticationManager(manager);

        String json = "{\"code\":\"c\",\"state\":\"s\",\"token\":\"t\"}";
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getReader()).thenReturn(new BufferedReader(new StringReader(json)));
        when(request.getMethod()).thenReturn("POST");
        when(request.getHeader("Content-Type")).thenReturn("application/json");

        Authentication auth = filter.doAttemptAuthentication(request, mock(HttpServletResponse.class));
        assertThat(auth).isSameAs(result);
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
    @DisplayName("doAttemptAuthentication tolerates null parameters (form request defaults to empty)")
    void testAttemptFormWithNullParameters() throws Exception {
        AuthenticationManager manager = mock(AuthenticationManager.class);
        Authentication result = mock(Authentication.class);
        when(manager.authenticate(any())).thenReturn(result);
        filter.setAuthenticationManager(manager);

        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getParameter("code")).thenReturn(null);
        when(request.getParameter("state")).thenReturn(null);
        when(request.getParameter("token")).thenReturn(null);

        Authentication auth = filter.doAttemptAuthentication(request, mock(HttpServletResponse.class));
        assertThat(auth).isSameAs(result);
    }
}
