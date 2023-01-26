/**
 * 
 */
package com.mozen.springbootkeycloack.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author Thwet Thwet Mar
 *
 *         Jan 25, 2023
 */
@ConfigurationProperties(prefix = "security")
public class AuthorizeURLConfig {
	private List<String> unauthorizeURLs = new ArrayList<String>();

	private List<String> unValidateNonceUrls = new ArrayList<String>();

	public List<String> getUnValidateNonceUrls() {
		return unValidateNonceUrls;
	}

	public List<String> getUnauthorizeURLs() {
		return unauthorizeURLs;
	}
}
