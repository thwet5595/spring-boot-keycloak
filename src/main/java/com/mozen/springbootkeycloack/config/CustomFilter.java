/**
 * 
 */
package com.mozen.springbootkeycloack.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozen.springbootkeycloack.custom.CustomTokenUtil;
import com.mozen.springbootkeycloack.custom.GenerateSecurityToken;
import com.mozen.springbootkeycloack.dto.GenerateTokenDto;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;

/**
 * @author Thwet Thwet Mar
 *
 *         Jan 25, 2023
 */
@Component
public class CustomFilter extends GenericFilterBean {
	private Logger logger = LogManager.getLogger(CustomFilter.class);
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
//		HttpServletRequest servletRequest = (HttpServletRequest) request;
//		HttpServletResponse servletResponse = (HttpServletResponse) response;
//
//		String deviceId = servletRequest.getHeader("deviceId");
//		logger.info("DeviceId{}", deviceId);
//		String securityToken = servletRequest.getHeader("wmt-mfs");
//		logger.info("SecurityToken{}", securityToken);
//		//processManagementEndpointUsernamePasswordAuthentication(deviceId, securityToken);
//		if (deviceId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//			UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
//					deviceId, null,new ArrayList<>());
//			usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(servletRequest));
//			SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
//
//		}
//		chain.doFilter(request, response);
		HttpServletRequest servletRequest = (HttpServletRequest) request;
		//List<String> unAuthUrls = unauthorizeURLConfig.getUnauthorizeURLs();
		
		String requestURL = servletRequest.getServletPath();
		boolean validateSecurityToken = true;
	
		
		HttpServletResponse servletResponse = (HttpServletResponse) response;
    	try {
        	if(validateSecurityToken) {
        		String deviceId = servletRequest.getHeader("deviceId");
        		
        		String securityToken = servletRequest.getHeader("wmt-mfs");
        		if(securityToken == null || securityToken.isEmpty()) {
        			//throw new BusinessLogicException(HttpStatus.UNAUTHORIZED, "WM103", "Invalid token.", null);
        		}
        		
    			/*Check token whether token is valid or not*/
    			JwtClaims jwtClaims = CustomTokenUtil.validateJWEAndReturnClaims(securityToken);
    			String sessionId = (String)jwtClaims.getClaimValue("sessionId");
    			String msisdn = (String)jwtClaims.getClaimValue("msisdn");
    			String password = (String)jwtClaims.getClaimValue("password");
    			String pin = (String)jwtClaims.getClaimValue("pin");    		
    			String userCategory = (String)jwtClaims.getClaimValue("userCategory");
    			
    			
    			//logger.debug(new ObjectMessage(new LogMessage("Security Token validation is success. TokenMsisdn: " + msisdn, null)));
    			servletRequest.setAttribute("msisdn", msisdn);    			
    			servletRequest.setAttribute("sessionId", sessionId);
    			servletRequest.setAttribute("pin", pin);
    			servletRequest.setAttribute("password", password);
    			servletRequest.setAttribute("userCategory", userCategory);
    			
    			/*Check nonce validation*/
    			String nonce = null;
    			try {
    				nonce = (String) jwtClaims.getJwtId();
    			} catch (MalformedClaimException e) {
    				//throw new BusinessLogicException(HttpStatus.UNAUTHORIZED, "JW12", e.getMessage(), null, e);
    			}
//    			
//    			List<String> unValidateNonceUrls = unauthorizeURLConfig.getUnValidateNonceUrls();
    			boolean validateNonce = true;
//    			if(unValidateNonceUrls != null) {
//    				for (String nonceUrl : unValidateNonceUrls) {
//        				if(requestURL.contains(nonceUrl)) {
//        					validateNonce = false;
//        				}
//        			}
//    			}
//    			
    			String nonceKey = msisdn + "_" + deviceId;
//    			if(validateNonce) {
//    				Object existingNonce = cacheDao.findByKey(nonceKey);
//        			if (nonce == null || existingNonce == null || !nonce.equals(existingNonce.toString())) {
//        				logger.debug(new ObjectMessage(new LogMessage("Nonce validation failed. Nonce value from cache: " + existingNonce + ". Nonce value from header: " + nonce + ". Key: " + nonceKey, null)));
//        				throw new BusinessLogicException(HttpStatus.UNAUTHORIZED, "WM103", "Invalid nonce.", new AmDocErrorCode("WM103"));
//        			}
//        			logger.debug(new ObjectMessage(new LogMessage("Nonce validation is success. Key: " + nonceKey, null)));
//    			}
    			
    
    			String newNonce = UUID.randomUUID().toString();
//    			if (userCategory != null) {
//    				if (userCategoryList.contains(userCategory.toLowerCase())) {
//    					cacheDao.save(nonceKey, newNonce, agentTokenTtlMin);
//    				} else {
//    					cacheDao.save(nonceKey, newNonce, tokenTtlMin);
//    				}
//    			} else {
//    				cacheDao.save(nonceKey, newNonce, tokenTtlMin);
//    			}
    	        GenerateTokenDto generateTokenDto = new GenerateTokenDto();
    			generateTokenDto.setSessionId(sessionId);
    			generateTokenDto.setMsisdn(msisdn);
    			generateTokenDto.setPassword(password);
    			generateTokenDto.setPin(pin);
    			generateTokenDto.setNonce(validateNonce ? newNonce : null);
    			generateTokenDto.setUserCategory(userCategory);
//    			if (userCategory != null) {
//    				if (userCategoryList.contains(userCategory.toLowerCase())) {
//    					generateTokenDto.setTtlMin(agentTokenTtlMin);
//    				} else {
//    					generateTokenDto.setTtlMin(tokenTtlMin);
//    				}
//    			} else {
//    				generateTokenDto.setTtlMin(tokenTtlMin);
//    			}
    			
    			generateTokenDto.setTtlMin(60);
    			
    			String jwt = GenerateSecurityToken.generateSecurityToken(generateTokenDto);
    			//logger.debug(new ObjectMessage(new LogMessage("Generated New Token: " + jwt, null)));
    			servletResponse.setHeader("wmt-mfs", jwt);
    			
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
						deviceId, null, new ArrayList<>());
				usernamePasswordAuthenticationToken
						.setDetails(new WebAuthenticationDetailsSource().buildDetails(servletRequest));
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

        	}
        	chain.doFilter(request, response);
    		
    	} catch (Exception ex) {
//    		ApiError apiError = ApiUtils.toApiErrorDTO(ex);
//    		servletResponse.setHeader("Content-Type", "application/json;charset=utf-8");
//			servletResponse.setStatus(ex.getHttpStatus().value());
//			servletResponse.getWriter().write(convertObjectToJson(apiError));    			
    	}
	}
	
	private String convertObjectToJson(Object object) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(object);
    }
}
