package com.fullstack2.question.service;

import java.util.Optional;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.fullstack2.question.entity.SiteUserEntity;
import com.fullstack2.question.exception.DataNotFoundException;
import com.fullstack2.question.repository.UserRepository;
import com.fullstack2.question.security.SecurityConfig;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class UserService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	
	public SiteUserEntity create(String username, String email, String password) {
		SiteUserEntity user = new SiteUserEntity();
		user.setUsername(username);
		user.setEmail(email);
		user.setPassword(passwordEncoder.encode(password));
		this.userRepository.save(user);
		return user;
	}
		
	//siteuserEntity 조회하는 메서드
	public SiteUserEntity getUser(String username) {
		
		Optional<SiteUserEntity> siteUser = this.userRepository.findByusername(username);
		if(siteUser.isPresent()) {
			return siteUser.get();
		}else {
			throw new DataNotFoundException("siteUser not found");
		}
	}
		
}
