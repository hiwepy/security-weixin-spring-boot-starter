package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityWeiXinProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityWeiXinProperties {

	public static final String PREFIX = "spring.security.weixin";

	/** Whether Enable WeiXin Authentication. */
	private boolean enabled = false;

}
