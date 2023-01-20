/**
 * 
 */
package com.mozen.springbootkeycloack.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.mozen.springbootkeycloack.config.JwtTokenUtil;
import com.mozen.springbootkeycloack.model.AuthRequest;
import com.mozen.springbootkeycloack.model.AuthResponse;
import com.mozen.springbootkeycloack.service.CustomUserDetailService;

/**
 * @author Thwet Thwet Mar
 *
 *         Jan 17, 2023
 */
@RestController
public class AuthController {
	@Autowired
	AuthenticationManager authManager;
	@Autowired
	JwtTokenUtil jwtUtil;
	@Autowired
	CustomUserDetailService userDetailService;

	@PostMapping("/auth/login")
	public ResponseEntity<?> login(@RequestBody @Valid AuthRequest request) {
		try {
			Authentication authentication = authManager
					.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

			System.out.println("Authentication Principal..." + authentication.getPrincipal());

			final UserDetails userDetails = userDetailService.loadUserByUsername(request.getEmail());
			String accessToken = jwtUtil.generateToken(userDetails);
			AuthResponse response = new AuthResponse(request.getEmail(), accessToken);

			return ResponseEntity.ok().body(response);

		} catch (BadCredentialsException ex) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		}
	}
}
