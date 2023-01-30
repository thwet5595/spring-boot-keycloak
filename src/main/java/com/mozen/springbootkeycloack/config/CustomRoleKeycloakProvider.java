/**
 * 
 */
package com.mozen.springbootkeycloack.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * @author Thwet Thwet Mar
 *
 *         Jan 30, 2023
 */
@Component("customRoleProvider")
public class CustomRoleKeycloakProvider implements AuthenticationProvider {

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		KeycloakAuthenticationToken authenticationToken = (KeycloakAuthenticationToken) authentication;
		KeycloakPrincipal principal = (KeycloakPrincipal) authenticationToken.getPrincipal();
		KeycloakSecurityContext session = principal.getKeycloakSecurityContext();
		AccessToken token = session.getToken();
		Map<String, Object> scopes = token.getOtherClaims();
		List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
//		for (String scope : scopes) {
//			grantedAuthorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
//		}
		for (String key : scopes.keySet()) {
			System.out.println(key + ":" + scopes.get(key));
			grantedAuthorities.add(new SimpleGrantedAuthority(scopes.get(key).toString()));
		}
		authentication = new KeycloakAuthenticationToken(authenticationToken.getAccount(),
				authenticationToken.isInteractive(), grantedAuthorities);

		return authentication;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// TODO Auto-generated method stub
		return KeycloakAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
