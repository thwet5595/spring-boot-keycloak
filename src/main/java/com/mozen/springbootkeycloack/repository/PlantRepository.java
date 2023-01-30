package com.mozen.springbootkeycloack.repository;

import com.mozen.springbootkeycloack.model.Plant;
import org.springframework.data.repository.CrudRepository;
/**
 * @author Thwet Thwet Mar
 *
 *         Jan 16, 2023
 */
public interface PlantRepository extends CrudRepository<Plant, Long> {
}
