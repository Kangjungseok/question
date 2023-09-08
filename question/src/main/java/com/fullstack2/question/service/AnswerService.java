package com.fullstack2.question.service;




import java.util.Date;

import org.springframework.stereotype.Service;

import com.fullstack2.question.entity.AnswerEntity;
import com.fullstack2.question.entity.QuestionEntity;
import com.fullstack2.question.entity.SiteUserEntity;
import com.fullstack2.question.repository.AnswerRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class AnswerService {

	
	private final AnswerRepository answerRepository;
	
	public AnswerEntity create(QuestionEntity question, String content, SiteUserEntity author) {
		
		AnswerEntity answer = new AnswerEntity();
		
		answer.setContent(content);
		answer.setCreateDate(new Date());
		answer.setQuestionEntity(question);
		answer.setAuthor(author);
		
		this.answerRepository.save(answer);
		
		return answer;
	}
}
