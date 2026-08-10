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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Unit tests for {@link WxMaAuthenticationToken}.
 *
 * <p>Verifies both constructors, principal/credentials accessors, the
 * authenticated flag lifecycle, {@code eraseCredentials} behaviour and the
 * guard rail that prevents promoting an unauthenticated token.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("WxMaAuthenticationToken Tests")
class WxMaAuthenticationTokenTest {

    private static final Collection<? extends GrantedAuthority> AUTHORITIES =
            Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"));

    @Test
    @DisplayName("Unauthenticated token exposes principal and credentials")
    void testUnauthenticatedToken() {
        WxMaLoginRequest principal = new WxMaLoginRequest("js", "sk", "u", "o", "s", "r", "e", "i", "t");
        WxMaAuthenticationToken token = new WxMaAuthenticationToken(principal, "true");

        assertThat(token.getPrincipal()).isSameAs(principal);
        assertThat(token.getCredentials()).isEqualTo("true");
        assertThat(token.isAuthenticated()).isFalse();
        assertThat(token.getAuthorities()).isEmpty();
    }

    @Test
    @DisplayName("Authenticated token carries authorities and is authenticated")
    void testAuthenticatedToken() {
        User principal = new User("admin", "password", AUTHORITIES);
        WxMaAuthenticationToken token = new WxMaAuthenticationToken(principal, "password", AUTHORITIES);

        assertThat(token.getPrincipal()).isSameAs(principal);
        assertThat(token.getCredentials()).isEqualTo("password");
        assertThat(token.isAuthenticated()).isTrue();
        assertThat(token.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("setAuthenticated(true) is rejected")
    void testSetAuthenticatedTrueRejected() {
        WxMaAuthenticationToken token = new WxMaAuthenticationToken("p", "c");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> token.setAuthenticated(true));
    }

    @Test
    @DisplayName("setAuthenticated(false) keeps the token unauthenticated")
    void testSetAuthenticatedFalse() {
        WxMaAuthenticationToken token = new WxMaAuthenticationToken("p", "c", AUTHORITIES);
        token.setAuthenticated(false);
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    @DisplayName("eraseCredentials clears the credentials")
    void testEraseCredentials() {
        WxMaAuthenticationToken token = new WxMaAuthenticationToken("p", "secret", AUTHORITIES);
        token.eraseCredentials();
        assertThat(token.getCredentials()).isNull();
    }

    @Test
    @DisplayName("Null principal and credentials are tolerated")
    void testNullPrincipalAndCredentials() {
        WxMaAuthenticationToken token = new WxMaAuthenticationToken(null, null);
        assertThat(token.getPrincipal()).isNull();
        assertThat(token.getCredentials()).isNull();
    }
}
