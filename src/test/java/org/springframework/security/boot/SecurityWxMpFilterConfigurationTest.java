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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.weixin.authentication.WxMpAuthenticationProcessingFilter;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link SecurityWxMpFilterConfiguration} and its inner
 * {@code WxMpWebSecurityCustomizerAdapter}.
 *
 * @author <a href="https://github.com/loong10k">[@Loong Wan]</a>
 * @since 1.0.0
 */
@DisplayName("SecurityWxMpFilterConfiguration Tests")
class SecurityWxMpFilterConfigurationTest {

    private SecurityWxMpFilterConfiguration configuration;

    @BeforeEach
    void setUp() {
        configuration = new SecurityWxMpFilterConfiguration();
    }

    @Test
    @DisplayName("Instance can be created via constructor")
    void testInstantiation() {
        assertThat(configuration).isNotNull();
    }

    @Test
    @DisplayName("wxMpAuthenticationProvider() builds a provider from the available services")
    void testWxMpAuthenticationProvider() {
        Object provider = configuration.wxMpAuthenticationProvider(
                emptyObjectProvider(), emptyObjectProvider(), emptyObjectProvider());
        assertThat(provider).isNotNull();
    }

    @Test
    @DisplayName("Inner adapter can be constructed and its filter wired")
    void testAdapterConstructionAndFilter() throws Exception {
        AuthenticationProvider authProvider = mock(AuthenticationProvider.class);
        SecurityWxMpFilterConfiguration.WxMpWebSecurityCustomizerAdapter adapter =
                newAdapter(singletonObjectProvider(authProvider), singletonObjectProvider(new ObjectMapper()));

        assertThat(adapter).isNotNull();
        assertThat(adapter.authenticationProcessingFilter())
                .isInstanceOf(WxMpAuthenticationProcessingFilter.class);
        assertThat(ReflectionTestUtils.getField(adapter, "objectMapper")).isInstanceOf(ObjectMapper.class);
        assertThat(ReflectionTestUtils.getField(adapter, "localeContextFilter")).isNull();
    }

    @Test
    @DisplayName("Inner adapter uses provided collaborators when present")
    void testAdapterConstructionWithCollaborators() throws Exception {
        RememberMeServices rememberMe = mock(RememberMeServices.class);
        SessionAuthenticationStrategy sessionStrategy = mock(SessionAuthenticationStrategy.class);
        MatchedAuthenticationEntryPoint entryPoint = mock(MatchedAuthenticationEntryPoint.class);
        MatchedAuthenticationSuccessHandler successHandler = mock(MatchedAuthenticationSuccessHandler.class);
        MatchedAuthenticationFailureHandler failureHandler = mock(MatchedAuthenticationFailureHandler.class);
        AccessDeniedHandler accessDeniedHandler = mock(AccessDeniedHandler.class);
        AuthenticationListener listener = mock(AuthenticationListener.class);
        AuthenticationProvider authProvider = mock(AuthenticationProvider.class);
        ObjectMapper objectMapper = new ObjectMapper();

        SecurityWxMpFilterConfiguration.WxMpWebSecurityCustomizerAdapter adapter =
                newAdapterWithCollaborators(accessDeniedHandler, authProvider, listener, entryPoint,
                        successHandler, failureHandler, objectMapper, rememberMe, sessionStrategy);

        assertThat(ReflectionTestUtils.getField(adapter, "rememberMeServices")).isSameAs(rememberMe);
        assertThat(ReflectionTestUtils.getField(adapter, "sessionAuthenticationStrategy")).isSameAs(sessionStrategy);
        assertThat(ReflectionTestUtils.getField(adapter, "objectMapper")).isSameAs(objectMapper);
        assertThat(ReflectionTestUtils.getField(adapter, "authenticationEntryPoint")).isNotNull();
        assertThat(ReflectionTestUtils.getField(adapter, "authenticationSuccessHandler")).isNotNull();
        assertThat(ReflectionTestUtils.getField(adapter, "authenticationFailureHandler")).isNotNull();
        assertThat(ReflectionTestUtils.getField(adapter, "accessDeniedHandler")).isNotNull();

        WxMpAuthenticationProcessingFilter filter = adapter.authenticationProcessingFilter();
        assertThat(filter).isNotNull();
    }

    @Test
    @DisplayName("authenticationManagerBean() builds a ProviderManager when a provider is available")
    void testAuthenticationManagerBeanWithProvider() throws Exception {
        AuthenticationProvider authProvider = mock(AuthenticationProvider.class);
        SecurityWxMpFilterConfiguration.WxMpWebSecurityCustomizerAdapter adapter =
                newAdapter(singletonObjectProvider(authProvider), singletonObjectProvider(new ObjectMapper()));
        assertThat(adapter.authenticationManagerBean()).isNotNull();
    }

    private SecurityWxMpFilterConfiguration.WxMpWebSecurityCustomizerAdapter newAdapter(
            ObjectProvider<AuthenticationProvider> authProviderProvider,
            ObjectProvider<ObjectMapper> objectMapperProvider) {
        SecurityBizProperties bizProperties = new SecurityBizProperties();
        SecuritySessionMgtProperties sessionMgtProperties = new SecuritySessionMgtProperties();
        SecurityWxMpAuthcProperties authcProperties = new SecurityWxMpAuthcProperties();
        authcProperties.setPathPattern("/weixin/mp/**");

        return new SecurityWxMpFilterConfiguration.WxMpWebSecurityCustomizerAdapter(
                bizProperties,
                sessionMgtProperties,
                authcProperties,
                emptyObjectProvider(),
                emptyObjectProvider(),
                authProviderProvider,
                emptyObjectProvider(),
                emptyObjectProvider(),
                emptyObjectProvider(),
                emptyObjectProvider(),
                objectMapperProvider,
                emptyObjectProvider(),
                emptyObjectProvider());
    }

    private SecurityWxMpFilterConfiguration.WxMpWebSecurityCustomizerAdapter newAdapterWithCollaborators(
            AccessDeniedHandler accessDeniedHandler,
            AuthenticationProvider authProvider,
            AuthenticationListener listener,
            MatchedAuthenticationEntryPoint entryPoint,
            MatchedAuthenticationSuccessHandler successHandler,
            MatchedAuthenticationFailureHandler failureHandler,
            ObjectMapper objectMapper,
            RememberMeServices rememberMe,
            SessionAuthenticationStrategy sessionStrategy) {
        SecurityBizProperties bizProperties = new SecurityBizProperties();
        SecuritySessionMgtProperties sessionMgtProperties = new SecuritySessionMgtProperties();
        SecurityWxMpAuthcProperties authcProperties = new SecurityWxMpAuthcProperties();
        authcProperties.setPathPattern("/weixin/mp/**");

        return new SecurityWxMpFilterConfiguration.WxMpWebSecurityCustomizerAdapter(
                bizProperties,
                sessionMgtProperties,
                authcProperties,
                singletonObjectProvider(accessDeniedHandler),
                emptyObjectProvider(),
                singletonObjectProvider(authProvider),
                singletonObjectProvider(listener),
                singletonObjectProvider(entryPoint),
                singletonObjectProvider(successHandler),
                singletonObjectProvider(failureHandler),
                singletonObjectProvider(objectMapper),
                singletonObjectProvider(rememberMe),
                singletonObjectProvider(sessionStrategy));
    }

    private static <T> ObjectProvider<T> emptyObjectProvider() {
        return new ObjectProvider<T>() {
            @Override
            public T getObject() {
                throw new IllegalStateException("no object");
            }

            @Override
            public T getIfAvailable() {
                return null;
            }

            @Override
            public Stream<T> stream() {
                return Stream.empty();
            }
        };
    }

    private static <T> ObjectProvider<T> singletonObjectProvider(T value) {
        return new ObjectProvider<T>() {
            @Override
            public T getObject() {
                return value;
            }

            @Override
            public T getIfAvailable() {
                return value;
            }

            @Override
            public Stream<T> stream() {
                return value == null ? Stream.empty() : Stream.of(value);
            }
        };
    }
}
