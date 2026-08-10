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

import cn.binarywang.wx.miniapp.api.WxMaService;
import cn.binarywang.wx.miniapp.api.WxMaUserService;
import cn.binarywang.wx.miniapp.bean.WxMaJscode2SessionResult;
import cn.binarywang.wx.miniapp.bean.WxMaPhoneNumberInfo;
import cn.binarywang.wx.miniapp.bean.WxMaUserInfo;
import me.chanjar.weixin.common.error.WxErrorException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationServiceException;
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
 * Unit tests for {@link WxMaAuthenticationProvider}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("WxMaAuthenticationProvider Tests")
class WxMaAuthenticationProviderTest {

    private WxMaService wxMaService;
    private UserDetailsServiceAdapter userDetailsService;
    private PasswordEncoder passwordEncoder;
    private WxMaAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        wxMaService = mock(WxMaService.class);
        userDetailsService = mock(UserDetailsServiceAdapter.class);
        passwordEncoder = mock(PasswordEncoder.class);
        provider = new WxMaAuthenticationProvider(wxMaService, userDetailsService, passwordEncoder);
    }

    @Test
    @DisplayName("Constructor stores collaborators (including nulls)")
    void testConstructor() {
        WxMaAuthenticationProvider nullProvider = new WxMaAuthenticationProvider(null, null, null);
        assertThat(nullProvider.getWxMaService()).isNull();
        assertThat(nullProvider.getUserDetailsService()).isNull();
        assertThat(nullProvider.getPasswordEncoder()).isNull();
    }

    @Test
    @DisplayName("Getters return collaborators")
    void testGetters() {
        assertThat(provider.getWxMaService()).isSameAs(wxMaService);
        assertThat(provider.getUserDetailsService()).isSameAs(userDetailsService);
        assertThat(provider.getPasswordEncoder()).isSameAs(passwordEncoder);
        assertThat(provider.getUserDetailsChecker()).isNotNull();
    }

    @Test
    @DisplayName("supports() accepts WxMaAuthenticationToken only")
    void testSupports() {
        assertThat(provider.supports(WxMaAuthenticationToken.class)).isTrue();
        assertThat(provider.supports(WxMpAuthenticationToken.class)).isFalse();
        assertThat(provider.supports(Object.class)).isFalse();
    }

    @Test
    @DisplayName("authenticate() exchanges jscode for session and returns an authenticated token")
    void testAuthenticateWithJscode() throws Exception {
        WxMaLoginRequest loginRequest = new WxMaLoginRequest("jscode", null, null, null, null, null, null, null, null);
        WxMaAuthenticationToken token = new WxMaAuthenticationToken(loginRequest, "true");

        WxMaJscode2SessionResult session = mock(WxMaJscode2SessionResult.class);
        when(session.getOpenid()).thenReturn("openid-1");
        when(session.getUnionid()).thenReturn("unionid-1");
        when(session.getSessionKey()).thenReturn("sessionKey-1");
        when(wxMaService.jsCode2SessionInfo("jscode")).thenReturn(session);

        UserDetails ud = new User("user", "pwd",
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
        when(userDetailsService.loadUserDetails(token)).thenReturn(ud);

        Authentication result = provider.authenticate(token);

        assertThat(result).isInstanceOf(WxMaAuthenticationToken.class);
        assertThat(result.isAuthenticated()).isTrue();
        // ud is a plain User (not a SecurityPrincipal) so the principal is the username
        assertThat(result.getPrincipal()).isEqualTo("user");
        assertThat(result.getCredentials()).isEqualTo("pwd");
        // login request enriched with session info
        assertThat(loginRequest.getOpenid()).isEqualTo("openid-1");
        assertThat(loginRequest.getUnionid()).isEqualTo("unionid-1");
        assertThat(loginRequest.getSessionKey()).isEqualTo("sessionKey-1");
    }

    @Test
    @DisplayName("authenticate() returns SecurityPrincipal-backed token when applicable")
    void testAuthenticateWithSecurityPrincipal() throws Exception {
        WxMaLoginRequest loginRequest = new WxMaLoginRequest("jscode", null, null, null, null, null, null, null, null);
        WxMaAuthenticationToken token = new WxMaAuthenticationToken(loginRequest, "true");

        when(wxMaService.jsCode2SessionInfo("jscode")).thenReturn(null);

        SecurityPrincipal principal = new SecurityPrincipal("admin", "pwd", "ROLE_ADMIN");
        when(userDetailsService.loadUserDetails(token)).thenReturn(principal);

        Authentication result = provider.authenticate(token);

        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal()).isSameAs(principal);
    }

    @Test
    @DisplayName("authenticate() skips jscode exchange when jscode is blank")
    void testAuthenticateWithoutJscode() throws Exception {
        WxMaLoginRequest loginRequest = new WxMaLoginRequest(null, null, null, null, null, null, null, null, null);
        WxMaAuthenticationToken token = new WxMaAuthenticationToken(loginRequest, "true");

        UserDetails ud = new User("user", "pwd", Collections.emptySet());
        when(userDetailsService.loadUserDetails(token)).thenReturn(ud);

        Authentication result = provider.authenticate(token);
        assertThat(result.isAuthenticated()).isTrue();
        verify(wxMaService, never()).jsCode2SessionInfo(anyString());
    }

    @Test
    @DisplayName("authenticate() decrypts phone number and user info when sessionKey+encryptedData+iv present")
    void testAuthenticateDecryptsUserInfo() throws Exception {
        WxMaLoginRequest loginRequest = new WxMaLoginRequest("jscode", null, null, null, null, null, "enc", "iv", null);
        WxMaAuthenticationToken token = new WxMaAuthenticationToken(loginRequest, "true");

        WxMaJscode2SessionResult session = mock(WxMaJscode2SessionResult.class);
        when(session.getSessionKey()).thenReturn("sessionKey-1");
        when(wxMaService.jsCode2SessionInfo("jscode")).thenReturn(session);

        WxMaUserService userService = mock(WxMaUserService.class);
        when(wxMaService.getUserService()).thenReturn(userService);

        WxMaPhoneNumberInfo phoneInfo = mock(WxMaPhoneNumberInfo.class);
        when(phoneInfo.getPhoneNumber()).thenReturn("13800000000");
        when(userService.getPhoneNoInfo("sessionKey-1", "enc", "iv")).thenReturn(phoneInfo);

        WxMaUserInfo userInfo = mock(WxMaUserInfo.class);
        when(userService.getUserInfo("sessionKey-1", "enc", "iv")).thenReturn(userInfo);

        UserDetails ud = new User("user", "pwd", Collections.emptySet());
        when(userDetailsService.loadUserDetails(token)).thenReturn(ud);

        provider.authenticate(token);

        assertThat(loginRequest.getPhoneNumberInfo()).isSameAs(phoneInfo);
        assertThat(loginRequest.getUserInfo()).isSameAs(userInfo);
    }

    @Test
    @DisplayName("authenticate() wraps WxErrorException as AuthenticationServiceException")
    void testAuthenticateWxErrorException() throws Exception {
        WxMaLoginRequest loginRequest = new WxMaLoginRequest("jscode", null, null, null, null, null, null, null, null);
        WxMaAuthenticationToken token = new WxMaAuthenticationToken(loginRequest, "true");

        when(wxMaService.jsCode2SessionInfo("jscode")).thenThrow(new WxErrorException("boom"));

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
        WxMaLoginRequest loginRequest = new WxMaLoginRequest(null, null, null, null, null, null, null, null, null);
        WxMaAuthenticationToken token = new WxMaAuthenticationToken(loginRequest, "true");

        UserDetails ud = new User("user", "pwd", false, true, true, false, Collections.emptySet());
        when(userDetailsService.loadUserDetails(token)).thenReturn(ud);

        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(AccountStatusException.class);
    }

    @Test
    @DisplayName("authenticate() tolerates phone-decryption failure (logged, not rethrown)")
    void testAuthenticatePhoneDecryptionFailure() throws Exception {
        WxMaLoginRequest loginRequest = new WxMaLoginRequest("jscode", null, null, null, null, null, "enc", "iv", null);
        WxMaAuthenticationToken token = new WxMaAuthenticationToken(loginRequest, "true");

        WxMaJscode2SessionResult session = mock(WxMaJscode2SessionResult.class);
        when(session.getSessionKey()).thenReturn("sessionKey-1");
        when(wxMaService.jsCode2SessionInfo("jscode")).thenReturn(session);

        WxMaUserService userService = mock(WxMaUserService.class);
        when(wxMaService.getUserService()).thenReturn(userService);
        when(userService.getPhoneNoInfo("sessionKey-1", "enc", "iv")).thenThrow(new RuntimeException("decrypt failed"));
        when(userService.getUserInfo("sessionKey-1", "enc", "iv")).thenReturn(mock(WxMaUserInfo.class));

        UserDetails ud = new User("user", "pwd", Collections.emptySet());
        when(userDetailsService.loadUserDetails(token)).thenReturn(ud);

        Authentication result = provider.authenticate(token);
        assertThat(result.isAuthenticated()).isTrue();
        assertThat(loginRequest.getPhoneNumberInfo()).isNull();
    }

    @Test
    @DisplayName("authenticate() surfaces user-info decryption failure as AuthenticationServiceException")
    void testAuthenticateUserInfoDecryptionFailure() throws Exception {
        WxMaLoginRequest loginRequest = new WxMaLoginRequest("jscode", null, null, null, null, null, "enc", "iv", null);
        WxMaAuthenticationToken token = new WxMaAuthenticationToken(loginRequest, "true");

        WxMaJscode2SessionResult session = mock(WxMaJscode2SessionResult.class);
        when(session.getSessionKey()).thenReturn("sessionKey-1");
        when(wxMaService.jsCode2SessionInfo("jscode")).thenReturn(session);

        WxMaUserService userService = mock(WxMaUserService.class);
        when(wxMaService.getUserService()).thenReturn(userService);
        when(userService.getPhoneNoInfo("sessionKey-1", "enc", "iv")).thenReturn(mock(WxMaPhoneNumberInfo.class));
        when(userService.getUserInfo("sessionKey-1", "enc", "iv")).thenThrow(new RuntimeException("userInfo failed"));

        assertThatThrownBy(() -> provider.authenticate(token))
                .isInstanceOf(AuthenticationServiceException.class);
    }

    @Test
    @DisplayName("setUserDetailsChecker overrides the default checker")
    void testSetUserDetailsChecker() {
        UserDetailsChecker checker = mock(UserDetailsChecker.class);
        provider.setUserDetailsChecker(checker);
        assertThat(provider.getUserDetailsChecker()).isSameAs(checker);
    }
}
