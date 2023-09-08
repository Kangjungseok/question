package com.fullstack2.question.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.fullstack2.question.entity.AnswerEntity;


public interface AnswerRepository extends JpaRepository<AnswerEntity, Integer>{

}
