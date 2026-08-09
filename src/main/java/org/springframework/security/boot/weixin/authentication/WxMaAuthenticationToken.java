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

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.util.Collection;

/**
 * Authentication token representing a WeChat Mini Program ({@code Ma}) login request
 * or an authenticated Mini Program principal.
 *
 * <p>Used as both the unauthenticated request token (carrying a
 * {@link WxMaLoginRequest} principal) and the authenticated result token (carrying
 * the resolved {@code UserDetails}).</p>
 *
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public class WxMaAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final Object principal;
    private Object credentials;

    /**
     * Create an unauthenticated token carrying the supplied login principal and
     * credentials.
     * @param principal the {@link WxMaLoginRequest} (or other principal) carried by this token
     * @param credentials the credentials (typically a placeholder such as {@code "true"})
     */
    public WxMaAuthenticationToken(Object principal, String credentials) {
        super((Collection<? extends GrantedAuthority>) null);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(false);
    }

    /**
     * Create an authenticated token with the supplied principal, credentials and
     * granted authorities.
     * @param principal the authenticated principal (e.g. {@code UserDetails})
     * @param credentials the authenticated credentials
     * @param authorities the granted authorities for the authenticated principal
     */
    public WxMaAuthenticationToken(Object principal,  Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true); // must use super, as we override
    }

    // ~ Methods
    // ========================================================================================================

    /**
     * Get the credentials proof (e.g. password or session key) carried by this token.
     * @return the credentials
     */
    @Override
	public Object getCredentials() {
		return this.credentials;
	}

    /**
     * Get the principal (e.g. {@link WxMaLoginRequest} or {@code UserDetails})
     * represented by this token.
     * @return the principal
     */
    @Override
	public Object getPrincipal() {
		return this.principal;
	}

    /**
     * Set whether this token is authenticated.
     *
     * <p>Setting {@code true} is rejected; an authenticated token must be created
     * through the constructor that accepts a list of granted authorities.</p>
     *
     * @param isAuthenticated {@code true} to mark the token as trusted (rejected), {@code false} to mark it unauthenticated
     * @throws IllegalArgumentException if {@code isAuthenticated} is {@code true}
     */
    @Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (isAuthenticated) {
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
        }

        super.setAuthenticated(false);
	}

    /**
     * Erase the credentials carried by this token.
     */
    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        credentials = null;
    }


}
