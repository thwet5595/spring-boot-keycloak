/**
 * 
 */
package com.mozen.springbootkeycloack.custom;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jose4j.jwt.JwtClaims;

import com.mozen.springbootkeycloack.dto.GenerateTokenDto;

/**
 * @author Thwet Thwet Mar
 *
 *         Jan 25, 2023
 */
public class GenerateSecurityToken {
	private static Logger logger = LogManager.getLogger(GenerateSecurityToken.class.getName());

	public static String generateSecurityToken(GenerateTokenDto generateTokenDto) {
		JwtClaims claims = new JwtClaims();
		claims.setClaim("sessionId", generateTokenDto.getSessionId());
		claims.setClaim("msisdn", generateTokenDto.getMsisdn());
		claims.setClaim("password", generateTokenDto.getPassword());
		claims.setClaim("pin", generateTokenDto.getPin());
		if (generateTokenDto.getUserCategory() != null) {
			claims.setClaim("userCategory", generateTokenDto.getUserCategory());
		} else {
			claims.setClaim("userCategory", "unknown");
		}
		claims.setJwtId(generateTokenDto.getNonce());
		logger.info("Claims: " + claims);
		String jws = CustomTokenUtil.createJWT(claims, generateTokenDto.getTtlMin());
		String jwt = CustomTokenUtil.createJWE(jws);
		logger.info("JWT Token(msisdn: " + generateTokenDto.getMsisdn() + "): " + claims);
		return jwt;
	}
}
