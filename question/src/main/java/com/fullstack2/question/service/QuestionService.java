package com.fullstack2.question.service;


import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;

import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.fullstack2.question.entity.QuestionEntity;
import com.fullstack2.question.entity.SiteUserEntity;
import com.fullstack2.question.exception.DataNotFoundException;
import com.fullstack2.question.repository.QuestionRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class QuestionService {

	private final QuestionRepository questionRepository;
	
	public List<QuestionEntity> getList(){
		return this.questionRepository.findAll();
	}
	
	public QuestionEntity getQuestion(Integer id) {
		Optional<QuestionEntity> question = this.questionRepository.findById(id);
		if(question.isPresent()) {
			return question.get();
		}else {
			throw new DataNotFoundException("question not found");
		}
		
	}
	
	//페이징
	public Page<QuestionEntity> getList(int page){
		List<Sort.Order> sorts = new ArrayList<>();
		sorts.add(Sort.Order.desc("createDate"));
		Pageable pageable = PageRequest.of(page , 10, Sort.by(sorts));
		return this.questionRepository.findAll(pageable);
	}
	
	
	//질문데이터 저장하는 create메서드
	public void create(String subject, String content, SiteUserEntity user) {
		QuestionEntity q = new QuestionEntity();
		q.setSubject(subject);
		q.setContent(content);
		q.setCreateDate(new Date());
		q.setAuthor(user);
		this.questionRepository.save(q);
	}
}
