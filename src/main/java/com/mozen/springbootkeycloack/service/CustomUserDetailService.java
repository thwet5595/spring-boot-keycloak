/**
 * 
 */
package com.mozen.springbootkeycloack.service;

import java.util.ArrayList;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author Thwet Thwet Mar
 *
 *         Jan 17, 2023
 */
@Service
public class CustomUserDetailService implements UserDetailsService {

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		if ("ttm@gmail.com".equals(username)) {
			return new User("ttm@gmail.com", "$2a$12$fFGbnc5FumNBsPyhPwmAueASABTRvrE/S0IM5n.paD6U0wW3VEfo.",
					new ArrayList<>());
		} else {
			throw new UsernameNotFoundException("User not found with username: " + username);
		}
	}
}
