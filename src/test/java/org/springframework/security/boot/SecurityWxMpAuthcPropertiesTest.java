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
package org.springframework.security.boot;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecurityRedirectProperties;
import org.springframework.security.boot.weixin.authentication.WxMaAuthenticationProcessingFilter;
import org.springframework.security.boot.weixin.authentication.WxMpAuthenticationProcessingFilter;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurityWxMpAuthcProperties}.
 *
 * <p>Verifies the configuration prefix, default parameter names, the nested
 * {@code redirect}/{@code logout} properties and the getter/setter contract.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecurityWxMpAuthcProperties Tests")
class SecurityWxMpAuthcPropertiesTest {

    private SecurityWxMpAuthcProperties properties;

    @BeforeEach
    void setUp() {
        properties = new SecurityWxMpAuthcProperties();
    }

    @Test
    @DisplayName("Configuration prefix is 'spring.security.weixin.mp'")
    void testPrefix() {
        assertThat(SecurityWxMpAuthcProperties.PREFIX).isEqualTo("spring.security.weixin.mp");
    }

    @Test
    @DisplayName("Default codeParameter matches the filter constant")
    void testDefaultCodeParameter() {
        assertThat(properties.getCodeParameter())
                .isEqualTo(WxMpAuthenticationProcessingFilter.SPRING_SECURITY_FORM_CODE_KEY);
    }

    @Test
    @DisplayName("Default tokenParameter matches the filter constant")
    void testDefaultTokenParameter() {
        assertThat(properties.getTokenParameter())
                .isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_TOKEN_KEY);
    }

    @Test
    @DisplayName("Setters update parameter values")
    void testSettersUpdateValues() {
        properties.setCodeParameter("c1");
        properties.setTokenParameter("t1");

        assertThat(properties.getCodeParameter()).isEqualTo("c1");
        assertThat(properties.getTokenParameter()).isEqualTo("t1");
    }

    @Test
    @DisplayName("Nested redirect and logout properties are initialised")
    void testNestedProperties() {
        assertThat(properties.getRedirect()).isNotNull().isInstanceOf(SecurityRedirectProperties.class);
        assertThat(properties.getLogout()).isNotNull().isInstanceOf(SecurityLogoutProperties.class);

        SecurityRedirectProperties redirect = new SecurityRedirectProperties();
        SecurityLogoutProperties logout = new SecurityLogoutProperties();
        properties.setRedirect(redirect);
        properties.setLogout(logout);
        assertThat(properties.getRedirect()).isSameAs(redirect);
        assertThat(properties.getLogout()).isSameAs(logout);
    }

    @Test
    @DisplayName("ToString returns a non-blank representation")
    void testToString() {
        assertThat(properties.toString()).isNotBlank();
    }
}
