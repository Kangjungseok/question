package com.fullstack2.question.entity;

import lombok.Getter;

@Getter
public enum UserRole {

	ADMIN("ROLE_ADMIN"), 
	USER("ROLE_USER");

	UserRole(String value) {
		this.value = value;
	}

	private String value;
}
