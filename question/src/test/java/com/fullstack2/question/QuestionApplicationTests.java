package com.fullstack2.question;

import java.sql.Date;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import com.fullstack2.question.entity.QuestionEntity;
import com.fullstack2.question.entity.SiteUserEntity;
import com.fullstack2.question.repository.QuestionRepository;
import com.fullstack2.question.service.QuestionService;

@SpringBootTest
class QuestionApplicationTests {

	
//	@Autowired
//	private QuestionRepository questionRepository;
//	
//	@Test
//	void contextLoads() {
//		
//		QuestionEntity qe = new QuestionEntity();
//		qe.setSubject("스프링부트가 무엇인가요??");
//		qe.setContent("스프링부트에 대해서 알고 싶습니다.");
//		this.questionRepository.save(qe);
//		
//		QuestionEntity qe2 = new QuestionEntity();
//		qe2.setSubject("두번째 테스트 제목입니다.");
//		qe2.setContent("스프링부트에 대해서 알고 싶습니다.라는 두번째 테스트의 내용입니다.");
//		this.questionRepository.save(qe2);
//		
//	}
	

//	@Autowired
//	private QuestionService questionService;
//	private SiteUserEntity siteUserEntity;
//	
//	@Test
//	void testJpa() {
//		for(int i = 1; i<= 100; i++) {
//			String subject = String.format("테스트 데이터입니다:[%03d]", i);
//            String content = "내용무";
//            this.questionService.create(subject, content, null);
//		}
//	}
}
