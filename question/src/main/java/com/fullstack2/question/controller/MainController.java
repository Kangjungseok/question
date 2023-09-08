package com.fullstack2.question.controller;


import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

public class MainController {

	@RequestMapping("/sbb")
	@ResponseBody
	public String index() {
		return "안녕하세요 sbb에 오신것을 환영합니다.";
	}
	
	@RequestMapping("/")
	public String root() {
		 return "redirect:/sbb";
	}
}
