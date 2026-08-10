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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurityWxProperties}.
 *
 * <p>Verifies the configuration prefix, default values and the
 * getter/setter contract for the {@code enabled} flag.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecurityWxProperties Tests")
class SecurityWxPropertiesTest {

    private SecurityWxProperties properties;

    @BeforeEach
    void setUp() {
        properties = new SecurityWxProperties();
    }

    @Test
    @DisplayName("Configuration prefix is 'spring.security.weixin'")
    void testPrefix() {
        assertThat(SecurityWxProperties.PREFIX).isEqualTo("spring.security.weixin");
    }

    @Test
    @DisplayName("Default value of enabled is false")
    void testDefaultEnabled() {
        assertThat(properties.isEnabled()).isFalse();
    }

    @Test
    @DisplayName("Setter for enabled updates the value")
    void testSetEnabled() {
        properties.setEnabled(true);
        assertThat(properties.isEnabled()).isTrue();
    }

    @Test
    @DisplayName("ToString returns a non-blank representation")
    void testToString() {
        assertThat(properties.toString()).contains("enabled");
    }
}
