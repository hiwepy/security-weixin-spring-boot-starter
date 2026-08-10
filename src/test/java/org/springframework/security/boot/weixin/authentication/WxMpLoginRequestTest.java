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
import me.chanjar.weixin.common.bean.WxOAuth2UserInfo;
import me.chanjar.weixin.common.bean.oauth2.WxOAuth2AccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link WxMpLoginRequest}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("WxMpLoginRequest Tests")
class WxMpLoginRequestTest {

    private WxMpLoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        loginRequest = new WxMpLoginRequest("code", "state", "token");
    }

    @Test
    @DisplayName("Constructor binds all arguments")
    void testConstructor() {
        assertThat(loginRequest.getCode()).isEqualTo("code");
        assertThat(loginRequest.getState()).isEqualTo("state");
        assertThat(loginRequest.getToken()).isEqualTo("token");
    }

    @Test
    @DisplayName("Default lang is zh_CN")
    void testDefaultLang() {
        assertThat(loginRequest.getLang()).isEqualTo("zh_CN");
    }

    @Test
    @DisplayName("Setters update each field")
    void testSetters() {
        loginRequest.setCode("c2");
        loginRequest.setState("s2");
        loginRequest.setToken("t2");
        loginRequest.setUnionid("u2");
        loginRequest.setOpenid("o2");
        loginRequest.setLang("en");

        assertThat(loginRequest.getCode()).isEqualTo("c2");
        assertThat(loginRequest.getState()).isEqualTo("s2");
        assertThat(loginRequest.getToken()).isEqualTo("t2");
        assertThat(loginRequest.getUnionid()).isEqualTo("u2");
        assertThat(loginRequest.getOpenid()).isEqualTo("o2");
        assertThat(loginRequest.getLang()).isEqualTo("en");
    }

    @Test
    @DisplayName("accessToken getter/setter")
    void testAccessToken() {
        assertThat(loginRequest.getAccessToken()).isNull();
        WxOAuth2AccessToken token = new WxOAuth2AccessToken();
        loginRequest.setAccessToken(token);
        assertThat(loginRequest.getAccessToken()).isSameAs(token);
    }

    @Test
    @DisplayName("userInfo getter/setter")
    void testUserInfo() {
        assertThat(loginRequest.getUserInfo()).isNull();
        WxOAuth2UserInfo userInfo = new WxOAuth2UserInfo();
        loginRequest.setUserInfo(userInfo);
        assertThat(loginRequest.getUserInfo()).isSameAs(userInfo);
    }

    @Test
    @DisplayName("JSON deserialization populates fields and ignores unknown properties")
    void testJsonDeserialization() throws Exception {
        String json = "{"
                + "\"code\":\"c1\","
                + "\"state\":\"s1\","
                + "\"token\":\"t1\","
                + "\"unknown\":\"value\""
                + "}";

        WxMpLoginRequest result = new ObjectMapper().readValue(json, WxMpLoginRequest.class);

        assertThat(result.getCode()).isEqualTo("c1");
        assertThat(result.getState()).isEqualTo("s1");
        assertThat(result.getToken()).isEqualTo("t1");
    }

    @Test
    @DisplayName("ToString returns a non-blank representation")
    void testToString() {
        assertThat(loginRequest.toString()).contains("code");
    }
}
