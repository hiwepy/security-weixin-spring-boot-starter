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

import cn.binarywang.wx.miniapp.bean.WxMaPhoneNumberInfo;
import cn.binarywang.wx.miniapp.bean.WxMaUserInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link WxMaLoginRequest}.
 *
 * <p>Verifies the constructor argument binding, the Lombok-generated
 * getters/setters and JSON deserialization.</p>
 *
 * @author <a href="https://github.com/loong10k">[@Loong Wan]</a>
 * @since 1.0.0
 */
@DisplayName("WxMaLoginRequest Tests")
class WxMaLoginRequestTest {

    private WxMaLoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        loginRequest = new WxMaLoginRequest("jscode", "sessionKey", "unionid", "openid",
                "signature", "rawData", "encryptedData", "iv", "token");
    }

    @Test
    @DisplayName("Constructor binds all arguments")
    void testConstructor() {
        assertThat(loginRequest.getJscode()).isEqualTo("jscode");
        assertThat(loginRequest.getSessionKey()).isEqualTo("sessionKey");
        assertThat(loginRequest.getUnionid()).isEqualTo("unionid");
        assertThat(loginRequest.getOpenid()).isEqualTo("openid");
        assertThat(loginRequest.getSignature()).isEqualTo("signature");
        assertThat(loginRequest.getRawData()).isEqualTo("rawData");
        assertThat(loginRequest.getEncryptedData()).isEqualTo("encryptedData");
        assertThat(loginRequest.getIv()).isEqualTo("iv");
        assertThat(loginRequest.getToken()).isEqualTo("token");
    }

    @Test
    @DisplayName("Setters update each field")
    void testSetters() {
        loginRequest.setJscode("js2");
        loginRequest.setSessionKey("sk2");
        loginRequest.setUnionid("u2");
        loginRequest.setOpenid("o2");
        loginRequest.setSignature("s2");
        loginRequest.setRawData("r2");
        loginRequest.setEncryptedData("e2");
        loginRequest.setIv("i2");
        loginRequest.setToken("t2");

        assertThat(loginRequest.getJscode()).isEqualTo("js2");
        assertThat(loginRequest.getSessionKey()).isEqualTo("sk2");
        assertThat(loginRequest.getUnionid()).isEqualTo("u2");
        assertThat(loginRequest.getOpenid()).isEqualTo("o2");
        assertThat(loginRequest.getSignature()).isEqualTo("s2");
        assertThat(loginRequest.getRawData()).isEqualTo("r2");
        assertThat(loginRequest.getEncryptedData()).isEqualTo("e2");
        assertThat(loginRequest.getIv()).isEqualTo("i2");
        assertThat(loginRequest.getToken()).isEqualTo("t2");
    }

    @Test
    @DisplayName("phoneNumberInfo getter/setter")
    void testPhoneNumberInfo() {
        assertThat(loginRequest.getPhoneNumberInfo()).isNull();
        WxMaPhoneNumberInfo info = new WxMaPhoneNumberInfo();
        loginRequest.setPhoneNumberInfo(info);
        assertThat(loginRequest.getPhoneNumberInfo()).isSameAs(info);
    }

    @Test
    @DisplayName("userInfo getter/setter")
    void testUserInfo() {
        assertThat(loginRequest.getUserInfo()).isNull();
        WxMaUserInfo userInfo = new WxMaUserInfo();
        loginRequest.setUserInfo(userInfo);
        assertThat(loginRequest.getUserInfo()).isSameAs(userInfo);
    }

    @Test
    @DisplayName("JSON deserialization populates fields and ignores unknown properties")
    void testJsonDeserialization() throws Exception {
        String json = "{"
                + "\"jscode\":\"jc\","
                + "\"sessionKey\":\"sk\","
                + "\"unionid\":\"un\","
                + "\"openid\":\"op\","
                + "\"signature\":\"sg\","
                + "\"rawData\":\"rd\","
                + "\"encryptedData\":\"ed\","
                + "\"iv\":\"iv\","
                + "\"token\":\"tk\","
                + "\"unknown\":\"value\""
                + "}";

        WxMaLoginRequest result = new ObjectMapper().readValue(json, WxMaLoginRequest.class);

        assertThat(result.getJscode()).isEqualTo("jc");
        assertThat(result.getSessionKey()).isEqualTo("sk");
        assertThat(result.getUnionid()).isEqualTo("un");
        assertThat(result.getOpenid()).isEqualTo("op");
        assertThat(result.getSignature()).isEqualTo("sg");
        assertThat(result.getRawData()).isEqualTo("rd");
        assertThat(result.getEncryptedData()).isEqualTo("ed");
        assertThat(result.getIv()).isEqualTo("iv");
        assertThat(result.getToken()).isEqualTo("tk");
    }

    @Test
    @DisplayName("ToString and equals are generated by Lombok")
    void testToStringAndEquals() {
        assertThat(loginRequest.toString()).contains("jscode");
        WxMaLoginRequest same = new WxMaLoginRequest("jscode", "sessionKey", "unionid", "openid",
                "signature", "rawData", "encryptedData", "iv", "token");
        assertThat(loginRequest).isEqualTo(same).hasSameHashCodeAs(same);
    }
}
