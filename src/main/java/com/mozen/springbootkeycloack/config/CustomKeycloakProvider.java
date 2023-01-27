/**
 * 
 */
package com.mozen.springbootkeycloack.config;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.account.KeycloakRole;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * @author Thwet Thwet Mar
 *
 *         Jan 27, 2023
 */
@Component("customProvider")
public class CustomKeycloakProvider implements AuthenticationProvider {

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		KeycloakAuthenticationToken authenticationToken = (KeycloakAuthenticationToken) authentication;
		KeycloakPrincipal principal = (KeycloakPrincipal) authenticationToken.getPrincipal();
		KeycloakSecurityContext session = principal.getKeycloakSecurityContext();
		AccessToken token = session.getToken();
		String[] scopes = token.getScope().split(" ");
		List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
		for (String scope : scopes) {
			grantedAuthorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
		}

		authentication = new KeycloakAuthenticationToken(authenticationToken.getAccount(),
				authenticationToken.isInteractive(), grantedAuthorities);

		return authentication;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return KeycloakAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
