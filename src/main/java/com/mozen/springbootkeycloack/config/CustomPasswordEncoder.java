/**
 * 
 */
package com.mozen.springbootkeycloack.config;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @author Thwet Thwet Mar
 *
 *         Jan 16, 2023
 */
@Component
public class CustomPasswordEncoder implements PasswordEncoder {

	@Override
	public String encode(CharSequence rawPassword) {
		String hashed = BCrypt.hashpw(rawPassword.toString(), BCrypt.gensalt(12));
		return hashed;
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
	}

	public static void main(String[]args) {
		String password = "password";
		System.out.println(" Password...." + password);
		CustomPasswordEncoder customPasswordEncoder = new CustomPasswordEncoder();
		String encoded = customPasswordEncoder.encode(password);

		System.out.println("Encode .." +encoded + "<<<Length>>>"
				+ customPasswordEncoder.encode(password).length());
		
		System.out.println("Matches.."+ customPasswordEncoder.matches("password", encoded));
	}
}
