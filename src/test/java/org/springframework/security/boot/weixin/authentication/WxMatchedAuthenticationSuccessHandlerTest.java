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
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserProfilePayload;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WxMatchedAuthenticationSuccessHandler}.
 *
 * @author <a href="https://github.com/loong10k">[@Loong Wan]</a>
 * @since 1.0.0
 */
@DisplayName("WxMatchedAuthenticationSuccessHandler Tests")
class WxMatchedAuthenticationSuccessHandlerTest {

    private JwtPayloadRepository payloadRepository;
    private WxMatchedAuthenticationSuccessHandler handler;

    @BeforeEach
    void setUp() {
        payloadRepository = mock(JwtPayloadRepository.class);
        handler = new WxMatchedAuthenticationSuccessHandler(payloadRepository);
        handler.setCheckExpiry(true);
    }

    @Test
    @DisplayName("Constructor stores the payload repository (including null)")
    void testConstructor() {
        assertThat(handler.getPayloadRepository()).isSameAs(payloadRepository);
        WxMatchedAuthenticationSuccessHandler nullHandler = new WxMatchedAuthenticationSuccessHandler(null);
        assertThat(nullHandler.getPayloadRepository()).isNull();
    }

    @Test
    @DisplayName("supports() returns true for WxMp/WxMa tokens and false otherwise")
    void testSupports() {
        Authentication mpToken = mock(WxMpAuthenticationToken.class);
        Authentication maToken = mock(WxMaAuthenticationToken.class);
        Authentication other = mock(Authentication.class);

        assertThat(handler.supports(mpToken)).isTrue();
        assertThat(handler.supports(maToken)).isTrue();
        assertThat(handler.supports(other)).isFalse();
    }

    @Test
    @DisplayName("onAuthenticationSuccess writes a success response with the profile payload")
    void testOnAuthenticationSuccess() throws Exception {
        WxMpAuthenticationToken token = new WxMpAuthenticationToken("principal", "cred");
        UserProfilePayload profile = new UserProfilePayload();
        profile.setUid("user-1");
        when(payloadRepository.getProfilePayload(token, true)).thenReturn(profile);

        MockHttpServletResponse response = new MockHttpServletResponse();
        handler.onAuthenticationSuccess(mock(HttpServletRequest.class), response, token);

        assertThat(JSON.parseObject(response.getContentAsString()).getInteger("code"))
                .isEqualTo(AuthResponseCode.SC_AUTHC_SUCCESS.getCode());
    }

    @Test
    @DisplayName("checkExpiry getter/setter")
    void testCheckExpiry() {
        handler.setCheckExpiry(false);
        assertThat(handler.isCheckExpiry()).isFalse();
        handler.setCheckExpiry(true);
        assertThat(handler.isCheckExpiry()).isTrue();
    }

    @Test
    @DisplayName("payloadRepository setter")
    void testPayloadRepositorySetter() {
        JwtPayloadRepository another = mock(JwtPayloadRepository.class);
        handler.setPayloadRepository(another);
        assertThat(handler.getPayloadRepository()).isSameAs(another);
    }
}
