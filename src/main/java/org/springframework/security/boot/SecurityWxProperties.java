package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Top-level configuration properties for the WeChat (WeiXin) Spring Security starter.
 *
 * <p>Binds properties under the {@code spring.security.weixin} prefix and gates the
 * activation of all WeChat authentication auto-configuration through the
 * {@code enabled} flag.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@ConfigurationProperties(prefix = SecurityWxProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityWxProperties {

	/** Configuration property prefix shared by all WeChat security properties. */
	public static final String PREFIX = "spring.security.weixin";

	/** Whether WeChat (WeiXin) authentication auto-configuration is enabled. Defaults to {@code false}. */
	private boolean enabled = false;

}
