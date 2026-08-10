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
package org.springframework.security.boot.weixin.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.exception.AuthResponseCode;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the WeChat exception hierarchy.
 *
 * <p>Covers {@link WxAuthenticationException}, {@link WxJsCodeExpiredException},
 * {@link WxJsCodeIncorrectException}, {@link WxJsCodeInvalidException} and
 * {@link WxJsCodeNotFoundException}.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("WeChat Exception Tests")
class WxExceptionsTest {

    @Test
    @DisplayName("WxAuthenticationException uses the third-party-service response code")
    void testWxAuthenticationException() {
        WxAuthenticationException ex = new WxAuthenticationException("oops");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_THIRD_PARTY_SERVICE.getCode());
        assertThat(ex.getMessage()).isEqualTo("oops");
        assertThat(ex.getCause()).isNull();

        Throwable cause = new RuntimeException("root");
        WxAuthenticationException ex2 = new WxAuthenticationException("oops", cause);
        assertThat(ex2.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_THIRD_PARTY_SERVICE.getCode());
        assertThat(ex2.getMessage()).isEqualTo("oops");
        assertThat(ex2.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("WxJsCodeExpiredException uses the code-expired response code")
    void testWxJsCodeExpiredException() {
        WxJsCodeExpiredException ex = new WxJsCodeExpiredException("expired");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED.getCode());
        assertThat(ex.getMessage()).isEqualTo("expired");
        assertThat(ex.getCause()).isNull();

        Throwable cause = new RuntimeException("root");
        WxJsCodeExpiredException ex2 = new WxJsCodeExpiredException("expired", cause);
        assertThat(ex2.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_CODE_EXPIRED.getCode());
        assertThat(ex2.getMessage()).isEqualTo("expired");
        assertThat(ex2.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("WxJsCodeIncorrectException uses the code-incorrect response code")
    void testWxJsCodeIncorrectException() {
        WxJsCodeIncorrectException ex = new WxJsCodeIncorrectException("bad");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT.getCode());
        assertThat(ex.getMessage()).isEqualTo("bad");
        assertThat(ex.getCause()).isNull();

        Throwable cause = new RuntimeException("root");
        WxJsCodeIncorrectException ex2 = new WxJsCodeIncorrectException("bad", cause);
        assertThat(ex2.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT.getCode());
        assertThat(ex2.getMessage()).isEqualTo("bad");
        assertThat(ex2.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("WxJsCodeInvalidException uses the code-invalid response code")
    void testWxJsCodeInvalidException() {
        WxJsCodeInvalidException ex = new WxJsCodeInvalidException("invalid");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_CODE_INVALID.getCode());
        assertThat(ex.getMessage()).isEqualTo("invalid");
        assertThat(ex.getCause()).isNull();

        Throwable cause = new RuntimeException("root");
        WxJsCodeInvalidException ex2 = new WxJsCodeInvalidException("invalid", cause);
        assertThat(ex2.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_CODE_INVALID.getCode());
        assertThat(ex2.getMessage()).isEqualTo("invalid");
        assertThat(ex2.getCause()).isSameAs(cause);
    }

    @Test
    @DisplayName("WxJsCodeNotFoundException uses the code-required response code")
    void testWxJsCodeNotFoundException() {
        WxJsCodeNotFoundException ex = new WxJsCodeNotFoundException("missing");
        assertThat(ex.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_CODE_REQUIRED.getCode());
        assertThat(ex.getMessage()).isEqualTo("missing");
        assertThat(ex.getCause()).isNull();

        Throwable cause = new RuntimeException("root");
        WxJsCodeNotFoundException ex2 = new WxJsCodeNotFoundException("missing", cause);
        assertThat(ex2.getCode()).isEqualTo(AuthResponseCode.SC_AUTHZ_CODE_REQUIRED.getCode());
        assertThat(ex2.getMessage()).isEqualTo("missing");
        assertThat(ex2.getCause()).isSameAs(cause);
    }
}
