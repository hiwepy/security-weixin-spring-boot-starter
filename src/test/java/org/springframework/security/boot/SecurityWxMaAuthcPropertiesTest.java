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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurityWxMaAuthcProperties}.
 *
 * <p>Verifies the configuration prefix, default parameter names, the nested
 * {@code redirect}/{@code logout} properties and the getter/setter contract.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecurityWxMaAuthcProperties Tests")
class SecurityWxMaAuthcPropertiesTest {

    private SecurityWxMaAuthcProperties properties;

    @BeforeEach
    void setUp() {
        properties = new SecurityWxMaAuthcProperties();
    }

    @Test
    @DisplayName("Configuration prefix is 'spring.security.weixin.ma'")
    void testPrefix() {
        assertThat(SecurityWxMaAuthcProperties.PREFIX).isEqualTo("spring.security.weixin.ma");
    }

    @Test
    @DisplayName("Default debug flag is false")
    void testDefaultDebug() {
        assertThat(properties.isDebug()).isFalse();
    }

    @Test
    @DisplayName("Setter for debug updates the value")
    void testSetDebug() {
        properties.setDebug(true);
        assertThat(properties.isDebug()).isTrue();
    }

    @Test
    @DisplayName("Default jscodeParameter matches the filter constant")
    void testDefaultJscodeParameter() {
        assertThat(properties.getJscodeParameter())
                .isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_JSCODE_KEY);
    }

    @Test
    @DisplayName("Default signatureParameter matches the filter constant")
    void testDefaultSignatureParameter() {
        assertThat(properties.getSignatureParameter())
                .isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_SIGNATURE_KEY);
    }

    @Test
    @DisplayName("Default rawDataParameter matches the filter constant")
    void testDefaultRawDataParameter() {
        assertThat(properties.getRawDataParameter())
                .isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_RAWDATA_KEY);
    }

    @Test
    @DisplayName("Default encryptedDataParameter matches the filter constant")
    void testDefaultEncryptedDataParameter() {
        assertThat(properties.getEncryptedDataParameter())
                .isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_ENCRYPTEDDATA_KEY);
    }

    @Test
    @DisplayName("Default ivParameter matches the filter constant")
    void testDefaultIvParameter() {
        assertThat(properties.getIvParameter())
                .isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_IV_KEY);
    }

    @Test
    @DisplayName("Default unionidParameter matches the filter constant")
    void testDefaultUnionidParameter() {
        assertThat(properties.getUnionidParameter())
                .isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_UNIONID_KEY);
    }

    @Test
    @DisplayName("Default openidParameter matches the filter constant")
    void testDefaultOpenidParameter() {
        assertThat(properties.getOpenidParameter())
                .isEqualTo(WxMaAuthenticationProcessingFilter.SPRING_SECURITY_FORM_OPENID_KEY);
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
        properties.setJscodeParameter("j1");
        properties.setSignatureParameter("s1");
        properties.setRawDataParameter("r1");
        properties.setEncryptedDataParameter("e1");
        properties.setIvParameter("i1");
        properties.setUnionidParameter("u1");
        properties.setOpenidParameter("o1");
        properties.setTokenParameter("t1");

        assertThat(properties.getJscodeParameter()).isEqualTo("j1");
        assertThat(properties.getSignatureParameter()).isEqualTo("s1");
        assertThat(properties.getRawDataParameter()).isEqualTo("r1");
        assertThat(properties.getEncryptedDataParameter()).isEqualTo("e1");
        assertThat(properties.getIvParameter()).isEqualTo("i1");
        assertThat(properties.getUnionidParameter()).isEqualTo("u1");
        assertThat(properties.getOpenidParameter()).isEqualTo("o1");
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
