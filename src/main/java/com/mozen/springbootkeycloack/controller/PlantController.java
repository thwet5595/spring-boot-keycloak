package com.mozen.springbootkeycloack.controller;

import com.mozen.springbootkeycloack.model.Plant;
import com.mozen.springbootkeycloack.service.PlantService;
import com.sun.istack.NotNull;
import lombok.extern.slf4j.Slf4j;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController()
@RequestMapping("/plant")
//@PreAuthorize("isAuthenticated()")
public class PlantController {

    private PlantService plantService;
    
    public PlantController(PlantService plantService) {
        this.plantService = plantService;
    }

    //@PreAuthorize("hasRole('casher')")
    @GetMapping("/{plantId}")
    public Plant getPlant(@PathVariable @NotNull Long plantId) {

        log.info("Request for plant " + plantId + " received");

        return plantService.getPlant(plantId);
    }
}
