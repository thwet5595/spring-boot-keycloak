package com.mozen.springbootkeycloack.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.mozen.springbootkeycloack.model.User;
/**
 * @author Thwet Thwet Mar
 *
 *         Jan 17, 2023
 */
@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
	
	Optional<User> findByEmail(String email);
	
}
