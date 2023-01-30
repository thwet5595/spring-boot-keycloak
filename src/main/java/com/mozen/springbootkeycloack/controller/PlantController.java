package com.mozen.springbootkeycloack.controller;

import com.mozen.springbootkeycloack.model.Plant;
import com.mozen.springbootkeycloack.service.PlantService;
import com.sun.istack.NotNull;
import lombok.extern.slf4j.Slf4j;

import java.security.Principal;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
/**
 * @author Thwet Thwet Mar
 *
 *         Jan 16, 2023
 */
@Slf4j
@RestController()
@RequestMapping("/plant")
@PreAuthorize("isAuthenticated()")
public class PlantController {

	private PlantService plantService;

	public PlantController(PlantService plantService) {
		this.plantService = plantService;
	}

	// @PreAuthorize("hasAnyAuthority('ROLE_casher') OR
	// hasAuthority('SCOPE_email')")
	@PreAuthorize("hasAnyAuthority('SCOPE_sale')")
	@GetMapping("/{plantId}")
	public Plant getPlantByScope(@PathVariable @NotNull Long plantId) {
		log.info("Inside request plant by scope...");
		log.info("Request for plant " + plantId + " received");
		KeycloakAuthenticationToken authentication = (KeycloakAuthenticationToken) SecurityContextHolder.getContext()
				.getAuthentication();

		//Principal principal = (Principal) authentication.getPrincipal();
		KeycloakPrincipal principal=(KeycloakPrincipal)authentication.getPrincipal();
		KeycloakSecurityContext session = principal.getKeycloakSecurityContext();
		AccessToken token = session.getToken();
		token.getScope();

		String userIdByToken = "";

		if (principal instanceof KeycloakPrincipal) {
			KeycloakPrincipal<KeycloakSecurityContext> kPrincipal = (KeycloakPrincipal<KeycloakSecurityContext>) principal;
			//IDToken token = kPrincipal.getKeycloakSecurityContext().getIdToken();
			//userIdByToken = token.getSubject();
		}

		return plantService.getPlant(plantId);
	}
	
	@PreAuthorize("hasAnyAuthority('+959794807902')")
	@GetMapping("/role/{plantId}")
	public Plant getPlantByRole(@PathVariable @NotNull Long plantId) {
		log.info("Inside requestPlantByRole....");
		log.info("Request for plant " + plantId + " received");
		KeycloakAuthenticationToken authentication = (KeycloakAuthenticationToken) SecurityContextHolder.getContext()
				.getAuthentication();

		//Principal principal = (Principal) authentication.getPrincipal();
		KeycloakPrincipal principal=(KeycloakPrincipal)authentication.getPrincipal();
		KeycloakSecurityContext session = principal.getKeycloakSecurityContext();
		AccessToken token = session.getToken();
		token.getScope();

		String userIdByToken = "";

		if (principal instanceof KeycloakPrincipal) {
			KeycloakPrincipal<KeycloakSecurityContext> kPrincipal = (KeycloakPrincipal<KeycloakSecurityContext>) principal;
			//IDToken token = kPrincipal.getKeycloakSecurityContext().getIdToken();
			//userIdByToken = token.getSubject();
		}

		return plantService.getPlant(plantId);
	}
	
	@PreAuthorize("@securityService.hasAccess(1)")
	@GetMapping("/test")
	public void testSecurityService() {
		 System.out.println("Printing ...");
	}
}
