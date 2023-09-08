package com.fullstack2.question.controller;

import java.security.Principal;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.fullstack2.question.entity.QuestionEntity;
import com.fullstack2.question.entity.SiteUserEntity;
import com.fullstack2.question.form.AnswerForm;
import com.fullstack2.question.form.QuestionForm;
import com.fullstack2.question.repository.QuestionRepository;
import com.fullstack2.question.service.QuestionService;
import com.fullstack2.question.service.UserService;

import jakarta.validation.Valid;

import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;

import lombok.RequiredArgsConstructor;

@RequestMapping("/question")
@Controller
@RequiredArgsConstructor
public class QuestionController {

	
	private final QuestionService questionService;
	private final UserService userService;
	
	//질문 리스트
	@RequestMapping("/list")
	public String list(Model model,
								@RequestParam(value = "page", defaultValue = "0")
								int page){
		Page<QuestionEntity> paging = this.questionService.getList(page);
		model.addAttribute("paging", paging);
		return "question_list";
	}
	
	//질문상세
	@RequestMapping(value = "/detail/{id}")
	public String detail(Model model, @PathVariable("id") Integer id,
			AnswerForm answerForm) {
		QuestionEntity question = this.questionService.getQuestion(id);
		model.addAttribute("question", question);
		return "question_detail";
	}
	
	//질문 등록하기
	@PreAuthorize("isAuthenticated()")
	@GetMapping("/create")
	public String questionCreate(QuestionForm questionForm) {
		
		return "question_form";
	}
	
	//질문 등록하기 버튼 컨트롤 추가하기
	@PreAuthorize("isAuthenticated()")
	@PostMapping("/create")
	public String questionCreate(@Valid QuestionForm questionForm,
			BindingResult bindingResult,
			Principal principal) {
		
		if(bindingResult.hasErrors()) { 
			return "question_form";
		}
		
		SiteUserEntity siteUser = this.userService.getUser(principal.getName());
		
		this.questionService.create(questionForm.getSubject(), questionForm.getContent()
				,siteUser);
		return "redirect:/question/list"; //질문 저장 후 질문목록으로 이동
		
	}
}
