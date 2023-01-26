/**
 * 
 */
package com.mozen.springbootkeycloack.custom;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.springframework.http.HttpStatus;

/**
 * @author Thwet Thwet Mar
 *
 *         Jan 25, 2023
 */
public class CustomTokenUtil {
	/* server deployment */
	private static String PRIVATE_KEY_FILE_FULL_PATH = "/Users/thwetthwetmar/DEV/MYPROJECT/Keycloak/spring-boot-keycloak/src/main/resources/mfsKeystore.jks";
	private static Logger logger = LogManager.getLogger(CustomTokenUtil.class.getName());

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		JwtClaims claims = new JwtClaims();
		claims.setClaim("sessionId", "sessionId1");
		claims.setClaim("msisdn", "9790303034");
		claims.setClaim("password", "3693");
		claims.setClaim("pin", "3693");
		try {
			String jwt = CustomTokenUtil.createJWT(claims, 10);
			logger.info("JWT Token : " + jwt);
			CustomTokenUtil.validateJWTAndReturnClaims(jwt);
			logger.info("=====================================================================================");
			String jwe = CustomTokenUtil.createJWE(jwt);
			logger.info("JWE Token : " + jwe);
			JwtClaims result = CustomTokenUtil.validateJWEAndReturnClaims(jwe);
			String msisdn = (String) result.getClaimValue("msisdn");
			System.out.println("========>" + msisdn);
		} catch (Exception e1) {
			e1.printStackTrace();
		}
	}

	protected static String createJWE(String jws) {
		String jwt = null;
		logger.info("Creating JWE");
		try {
			JsonWebEncryption jwe = new JsonWebEncryption();
			jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA1_5);
			String encAlg = ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256;
			jwe.setEncryptionMethodHeaderParameter(encAlg);
			jwe.setKey((RSAPublicKey) getPublicKey("password", "selfsigned"));
			jwe.setKeyIdHeaderValue("mfs");
			jwe.setContentTypeHeaderValue("JWT");
			jwe.setPayload(jws);
			jwt = jwe.getCompactSerialization();
			logger.info("JWE has been Serializated");
		} catch (JoseException e1) {
			logger.error("Error Creating JWE: " + e1.getMessage(), e1);
			// throw new BusinessLogicException(HttpStatus.UNAUTHORIZED, "JW01",
			// e1.getMessage(), null, e1);
		}
		if (jwt == null) {
			// throw new BusinessLogicException(HttpStatus.UNAUTHORIZED, "JW02", "Error
			// creating JWE", null);
		}
		return jwt;
	}

	protected static String createJWT(JwtClaims claims, int securityTokenValidityInMinutes) {
		String jwt = "";
		logger.info("Creating JWT");
		claims.setIssuer("WM");
		claims.setAudience("WMT-MFS");
		claims.setExpirationTimeMinutesInTheFuture(securityTokenValidityInMinutes);
		claims.setIssuedAtToNow();
		claims.setNotBeforeMinutesInThePast(2);
		claims.setSubject("WMT-MFS");
		try {
			JsonWebSignature jws = new JsonWebSignature();
			jws.setPayload(claims.toJson());
			jws.setKey((RSAPrivateKey) getPrivateKey("password", "selfsigned"));
			jws.setKeyIdHeaderValue("mfs");
			jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA512);
			jwt = jws.getCompactSerialization();
			logger.info("JWT has been Serializated");
		} catch (Exception e1) {
			logger.error("Error Serializing JWT. Message: " + e1.getMessage(), e1);
			// throw new BusinessLogicException(HttpStatus.UNAUTHORIZED, "JW05",
			// e1.getMessage(), null, e1);
		}
		if (jwt == null) {
			// throw new BusinessLogicException(HttpStatus.INTERNAL_SERVER_ERROR, "JW06",
			// "Error creating JWT", null);
		}
		return jwt;
	}

	public static JwtClaims validateJWEAndReturnClaims(String jwt) {
		JwtClaims jwtClaims = null;
		logger.info("Validating JWE");
		try {
			JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime()
					.setAllowedClockSkewInSeconds(30).setRequireSubject().setExpectedIssuer("WM")
					.setExpectedAudience("WMT-MFS")
					.setDecryptionKey((RSAPrivateKey) getPrivateKey("password", "selfsigned"))
					.setVerificationKey((RSAPublicKey) getPublicKey("password", "selfsigned"))
					.setJwsAlgorithmConstraints(
							new AlgorithmConstraints(ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA512))
					.setJweAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST,
							KeyManagementAlgorithmIdentifiers.RSA1_5))
					.setJweContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST,
							ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256))
					.build();
			jwtClaims = jwtConsumer.processToClaims(jwt);
			logger.info("JWE validation succeeded! " + jwtClaims);
		} catch (InvalidJwtException e) {
			handleInvalidJwtException(e);
		}
		return jwtClaims;
	}

	public static JwtClaims validateJWE4FinOpsAndReturnClaims(String jwt) {
		return validateJWEAndReturnClaims(jwt);
	}

	public static JwtClaims validateJWTAndReturnClaims(String jwt) {
		JwtClaims jwtClaims = null;
		logger.info("Validating JWT");
		try {
			JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime()
					.setAllowedClockSkewInSeconds(30).setRequireSubject().setExpectedIssuer("WM")
					.setExpectedAudience("WMT-MFS")
					.setVerificationKey((RSAPublicKey) getPublicKey("password", "selfsigned")) // verify
					.setJwsAlgorithmConstraints(
							new AlgorithmConstraints(ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA512))
					.build();
			jwtClaims = jwtConsumer.processToClaims(jwt);
			logger.debug("JWT validation succeeded! " + jwtClaims);

		} catch (InvalidJwtException e) {
			handleInvalidJwtException(e);
		}
		return jwtClaims;
	}

	private static void handleInvalidJwtException(InvalidJwtException e) {
		logger.error("Invalid JWT! " + e.getMessage(), e);
		if (e.hasExpired()) {
			NumericDate expTime = null;
			try {
				expTime = e.getJwtContext().getJwtClaims().getExpirationTime();
				logger.error("JWT expired at " + expTime);
			} catch (MalformedClaimException e1) {
				logger.error("JWT Malformed Claim Exception JWT! " + e1.getMessage(), e1);
				// throw new BusinessLogicException(HttpStatus.UNAUTHORIZED, "JW08",
				// e1.getMessage(), null, e1);
			}
			// throw new BusinessLogicException(HttpStatus.UNAUTHORIZED, "JW09", "JWT
			// expired at " + expTime, null, e);
		}
		if (e.hasErrorCode(ErrorCodes.AUDIENCE_INVALID)) {
			List<String> tmpAudience = null;
			try {
				tmpAudience = e.getJwtContext().getJwtClaims().getAudience();
			} catch (MalformedClaimException e1) {
				logger.error("JWT Malformed Claim Exception JWT: " + e1.getMessage(), e1);
				// throw new BusinessLogicException(HttpStatus.UNAUTHORIZED, "JW08",
				// e1.getMessage(), null, e1);
			}
			// throw new BusinessLogicException(HttpStatus.UNAUTHORIZED, "JW11", "JWT
			// Audience Invalid " + tmpAudience.toString(), null, e);
		}
		// throw new BusinessLogicException(HttpStatus.UNAUTHORIZED, "JW12",
		// e.getMessage(), null, e);
	}

	private static PrivateKey getPrivateKey(String password, String alias) {
		PrivateKey privateKey = null;
		try {
			KeyStore keystore = KeyStore.getInstance("JKS");
			InputStream is = new FileInputStream(PRIVATE_KEY_FILE_FULL_PATH);
			keystore.load(is, password.toCharArray());
			privateKey = (PrivateKey) keystore.getKey(alias, password.toCharArray());
		} catch (Exception e) {
			logger.error("Failed to retrieve private key from keystore");
			// throw new BusinessLogicException(HttpStatus.INTERNAL_SERVER_ERROR, "JW28",
			// "Error getting PK", null, e);
		}
		return privateKey;
	}

	private static PublicKey getPublicKey(String password, String alias) {
		Key key = null;
		PublicKey publicKey = null;
		try {
			KeyStore keystore = KeyStore.getInstance("JKS");
			InputStream is = new FileInputStream(PRIVATE_KEY_FILE_FULL_PATH);
			keystore.load(is, password.toCharArray());
			key = keystore.getKey(alias, password.toCharArray());
			if (key instanceof PrivateKey) {
				Certificate cert = keystore.getCertificate(alias);
				publicKey = cert.getPublicKey();
			} else {
				logger.info("Invalid Public Key");
			}
		} catch (Exception e) {
			logger.error("Failed to retrieve public key from keystore");
			// throw new BusinessLogicException(HttpStatus.INTERNAL_SERVER_ERROR, "JW29",
			// "Failed to retrieve public key from keystore", null, e);
		}
		return publicKey;
	}
}
