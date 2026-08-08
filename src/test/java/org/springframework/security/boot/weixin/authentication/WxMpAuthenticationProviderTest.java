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

import me.chanjar.weixin.common.bean.WxOAuth2UserInfo;
import me.chanjar.weixin.common.bean.oauth2.WxOAuth2AccessToken;
import me.chanjar.weixin.common.error.WxErrorException;
import me.chanjar.weixin.common.service.WxOAuth2Service;
import me.chanjar.weixin.mp.api.WxMpService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WxMpAuthenticationProvider}.
 *
 * @author <a href="https://github.com/loong10k">[@Loong Wan]</a>
 * @since 1.0.0
 */
@DisplayName("WxMpAuthenticationProvider Tests")
class WxMpAuthenticationProviderTest {

    private WxMpService wxMpService;
    private UserDetailsServiceAdapter userDetailsService;
    private PasswordEncoder passwordEncoder;
    private WxMpAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        wxMpService = mock(WxMpService.class);
        userDetailsService = mock(UserDetailsServiceAdapter.class);
        passwordEncoder = mock(PasswordEncoder.class);
        provider = new WxMpAuthenticationProvider(wxMpService, userDetailsService, passwordEncoder);
    }

    @Test
    @DisplayName("Constructor stores collaborators (including nulls)")
    void testConstructor() {
        WxMpAuthenticationProvider nullProvider = new WxMpAuthenticationProvider(null, null, null);
        assertThat(nullProvider.getWxMpService()).isNull();
        assertThat(nullProvider.getUserDetailsService()).isNull();
        assertThat(nullProvider.getPasswordEncoder()).isNull();
    }

    @Test
    @DisplayName("Getters return collaborators")
    void testGetters() {
        assertThat(provider.getWxMpService()).isSameAs(wxMpService);
        assertThat(provider.getUserDetailsService()).isSameAs(userDetailsService);
        assertThat(provider.getPasswordEncoder()).isSameAs(passwordEncoder);
        assertThat(provider.getUserDetailsChecker()).isNotNull();
    }

    @Test
    @DisplayName("supports() accepts WxMpAuthenticationToken only")
    void testSupports() {
        assertThat(provider.supports(WxMpAuthenticationToken.class)).isTrue();
        assertThat(provider.supports(WxMaAuthenticationToken.class)).isFalse();
        assertThat(provider.supports(Object.class)).isFalse();
    }

    @Test
    @DisplayName("authenticate() exchanges code for access token and returns an authenticated token")
    void testAuthenticateWithCode() throws Exception {
        WxMpLoginRequest loginRequest = new WxMpLoginRequest("code", null, null);
        WxMpAuthenticationToken token = new WxMpAuthenticationToken(loginRequest, "true");

        WxOAuth2Service oAuth2Service = mock(WxOAuth2Service.class);
        when(wxMpService.getOAuth2Service()).thenReturn(oAuth2Service);

        WxOAuth2AccessToken accessToken = mock(WxOAuth2AccessToken.class);
        when(accessToken.getOpenId()).thenReturn("openid-1");
        when(accessToken.getUnionId()).thenReturn("unionid-1");
        when(oAuth2Service.getAccessToken("code")).thenReturn(accessToken);

        WxOAuth2UserInfo userInfo = mock(WxOAuth2UserInfo.class);
        when(oAuth2Service.getUserInfo(accessToken, "zh_CN")).thenReturn(userInfo);

        UserDetails ud = new User("user", "pwd",
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        when(userDetailsService.loadUserDetails(token)).thenReturn(ud);

        Authentication result = provider.authenticate(token);

        assertThat(result).isInstanceOf(WxMaAuthenticationToken.class);
        assertThat(result.isAuthenticated()).isTrue();
        // ud is a plain User (not a SecurityPrincipal) so the principal is the username
        assertThat(result.getPrincipal()).isEqualTo("user");
        assertThat(loginRequest.getAccessToken()).isSameAs(accessToken);
        assertThat(loginRequest.getOpenid()).isEqualTo("openid-1");
        assertThat(loginRequest.getUnionid()).isEqualTo("unionid-1");
        assertThat(loginRequest.getUserInfo()).isSameAs(userInfo);
    }

    @Test
    @DisplayName("authenticate() returns SecurityPrincipal-backed token when applicable")
    void testAuthenticateWithSecurityPrincipal() throws Exception {
        WxMpLoginRequest loginRequest = new WxMpLoginRequest("code", null, null);
        WxMpAuthenticationToken token = new WxMpAuthenticationToken(loginRequest, "true");

        WxOAuth2Service oAuth2Service = mock(WxOAuth2Service.class);
        when(wxMpService.getOAuth2Service()).thenReturn(oAuth2Service);
        when(oAuth2Service.getAccessToken("code")).thenReturn(null);

        SecurityPrincipal principal = new SecurityPrincipal("admin", "pwd", "ROLE_ADMIN");
        when(userDetailsService.loadUserDetails(token)).thenReturn(principal);

        Authentication result = provider.authenticate(token);
        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal()).isSameAs(principal);
    }

    @Test
    @DisplayName("authenticate() skips code exchange when code is blank")
    void testAuthenticateWithoutCode() throws Exception {
        WxMpLoginRequest loginRequest = new WxMpLoginRequest(null, null, null);
        WxMpAuthenticationToken token = new WxMpAuthenticationToken(loginRequest, "true");

        UserDetails ud = new User("user", "pwd", Collections.emptySet());
        when(userDetailsService.loadUserDetails(token)).thenReturn(ud);

        Authentication result = provider.authenticate(token);
        assertThat(result.isAuthenticated()).isTrue();
        verify(wxMpService, never()).getOAuth2Service();
    }

    @Test
    @DisplayName("authenticate() wraps WxErrorException as AuthenticationServiceException")
    void testAuthenticateWxErrorException() throws Exception {
        WxMpLoginRequest loginRequest = new WxMpLoginRequest("code", null, null);
        WxMpAuthenticationToken token = new WxMpAuthenticationToken(loginRequest, "true");

        WxOAuth2Service oAuth2Service = mock(WxOAuth2Service.class);
        when(wxMpService.getOAuth2Service()).thenReturn(oAuth2Service);
        when(oAuth2Service.getAccessToken("code")).thenThrow(new WxErrorException("boom"));

        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(AuthenticationServiceException.class)
                .hasMessageContaining("微信登录认证失败");
    }

    @Test
    @DisplayName("authenticate() rejects null authentication")
    void testAuthenticateNull() {
        assertThatThrownBy(() -> provider.authenticate(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("authenticate() surfaces user-status check failures")
    void testAuthenticateUserDetailsCheckFails() throws Exception {
        WxMpLoginRequest loginRequest = new WxMpLoginRequest(null, null, null);
        WxMpAuthenticationToken token = new WxMpAuthenticationToken(loginRequest, "true");

        UserDetails ud = new User("user", "pwd", false, true, true, false, Collections.emptySet());
        when(userDetailsService.loadUserDetails(token)).thenReturn(ud);

        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(LockedException.class);
    }

    @Test
    @DisplayName("setUserDetailsChecker overrides the default checker")
    void testSetUserDetailsChecker() {
        UserDetailsChecker checker = mock(UserDetailsChecker.class);
        provider.setUserDetailsChecker(checker);
        assertThat(provider.getUserDetailsChecker()).isSameAs(checker);
    }
}
