package com.fullstack2.question.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import com.fullstack2.question.entity.QuestionEntity;


import java.util.List;


public interface QuestionRepository extends JpaRepository<QuestionEntity, Integer>{

	QuestionEntity findBySubject(String subject);
	QuestionEntity findBySubjectAndContent(String subject, String content);
	List<QuestionEntity> findBySubjectLike(String subject);
	Page<QuestionEntity> findAll(Pageable pageable);
	
}
