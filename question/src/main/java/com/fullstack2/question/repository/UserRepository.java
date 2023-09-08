package com.fullstack2.question.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.fullstack2.question.entity.SiteUserEntity;

public interface UserRepository extends JpaRepository<SiteUserEntity, Long>{

	Optional<SiteUserEntity> findByusername(String username);
}
