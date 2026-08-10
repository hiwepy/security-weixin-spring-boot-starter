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

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.boot.weixin.exception.WxAuthenticationException;
import org.springframework.security.boot.weixin.exception.WxJsCodeExpiredException;
import org.springframework.security.boot.weixin.exception.WxJsCodeIncorrectException;
import org.springframework.security.boot.weixin.exception.WxJsCodeInvalidException;
import org.springframework.security.boot.weixin.exception.WxJsCodeNotFoundException;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link WxMatchedAuthenticationFailureHandler}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("WxMatchedAuthenticationFailureHandler Tests")
class WxMatchedAuthenticationFailureHandlerTest {

    private WxMatchedAuthenticationFailureHandler handler;

    @BeforeEach
    void setUp() {
        handler = new WxMatchedAuthenticationFailureHandler();
    }

    @Test
    @DisplayName("supports() returns true for WeChat exceptions and false otherwise")
    void testSupports() {
        assertThat(handler.supports(new WxAuthenticationException("x"))).isTrue();
        assertThat(handler.supports(new WxJsCodeExpiredException("x"))).isTrue();
        assertThat(handler.supports(new WxJsCodeIncorrectException("x"))).isTrue();
        assertThat(handler.supports(new WxJsCodeInvalidException("x"))).isTrue();
        assertThat(handler.supports(new WxJsCodeNotFoundException("x"))).isTrue();
        assertThat(handler.supports(new AuthenticationException("other") {
        })).isFalse();
    }

    @Test
    @DisplayName("onAuthenticationFailure() renders the code-expired branch")
    void testFailureExpired() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(mock(HttpServletRequest.class), response, new WxJsCodeExpiredException("expired"));
        assertThat(JSON.parseObject(response.getContentAsString()).getInteger("code"))
                .isEqualTo(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED.getCode());
    }

    @Test
    @DisplayName("onAuthenticationFailure() renders the code-invalid branch")
    void testFailureInvalid() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(mock(HttpServletRequest.class), response, new WxJsCodeInvalidException("invalid"));
        assertThat(JSON.parseObject(response.getContentAsString()).getInteger("code"))
                .isEqualTo(AuthResponseCode.SC_AUTHZ_CODE_INVALID.getCode());
    }

    @Test
    @DisplayName("onAuthenticationFailure() renders the code-incorrect branch")
    void testFailureIncorrect() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(mock(HttpServletRequest.class), response, new WxJsCodeIncorrectException("bad"));
        assertThat(JSON.parseObject(response.getContentAsString()).getInteger("code"))
                .isEqualTo(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT.getCode());
    }

    @Test
    @DisplayName("onAuthenticationFailure() renders the default fallback branch")
    void testFailureFallback() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationFailure(mock(HttpServletRequest.class), response, new WxAuthenticationException("generic"));
        assertThat(JSON.parseObject(response.getContentAsString()).getInteger("code"))
                .isEqualTo(AuthResponseCode.SC_AUTHZ_FAIL.getCode());
    }
}
