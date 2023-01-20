/**
 * 
 */
package com.mozen.springbootkeycloack.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Thwet Thwet Mar
 *
 *         Jan 16, 2023
 */
@RestController
@RequestMapping("/api")
public class HelloWorldController {
	@RequestMapping({ "/hello" })
	public String firstPage() {
		return "Hello World";
	}

}
