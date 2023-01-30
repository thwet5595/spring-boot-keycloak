/**
 * 
 */
package com.mozen.springbootkeycloack.service;

import org.springframework.stereotype.Service;

/**
 * @author Thwet Thwet Mar
 *
 *         Jan 30, 2023
 */
@Service
public class SecurityService {
	public boolean hasAccess(int parameter) {
		return parameter == 1;
	}
}
