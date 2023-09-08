package com.fullstack2.question.controller;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.fullstack2.question.entity.QuestionEntity;
import com.fullstack2.question.entity.SiteUserEntity;
import com.fullstack2.question.form.AnswerForm;
import com.fullstack2.question.service.AnswerService;
import com.fullstack2.question.service.QuestionService;
import com.fullstack2.question.service.UserService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RequestMapping("/answer")
@RequiredArgsConstructor
@Controller
public class AnswerController {

	private final QuestionService questionService;
	private final AnswerService answerService;
	private final UserService userService;
	
//	@PostMapping("/create/{id}")
//	public String creatAnswer(Model model, @PathVariable("id") Integer id,
//			@RequestParam String content) {
//		
//		QuestionEntity question = this.questionService.getQuestion(id);
//		this.answerService.create(question, content); //답변저장
//		return String.format("redirect:/question/detail/%s", id);
//	}
	
	@PreAuthorize("isAuthenticated()")
	@PostMapping("/create/{id}")/*AnswerForm을 사용하도록 컨트롤러 변경*/
    public String createAnswer(Model model, @PathVariable("id") Integer id,
                               @Valid AnswerForm answerForm, BindingResult bindingResult,
                               Principal principal) {
		
        QuestionEntity question = this.questionService.getQuestion(id);
        SiteUserEntity siteUser = this.userService.getUser(principal.getName());
        
        if(bindingResult.hasErrors()){
            model.addAttribute("question", question);
            return "question_detail";
        }
        this.answerService.create(question, answerForm.getContent(), siteUser);
        return String.format("redirect:/question/detail/%s", id);
    }
}
