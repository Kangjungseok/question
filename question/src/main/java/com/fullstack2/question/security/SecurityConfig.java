package com.fullstack2.question.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fullstack2.question.service.UserSecurityService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	 private final UserSecurityService userSecurityService;

	    @Bean
	    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	        /*스프링 시큐리티의 세부 설정은 SecurityFilterChain 빈을 생성하여 설정 가능*/

	        /* 모든 인증되지 않은 요청을 허락한다는 의미 - 로그인하지않더라도 모든페이지에 접근가능*/
	        http.authorizeRequests().requestMatchers("/**").permitAll()

	                /*스프링 시큐리티의 로그인 설정을 담당하는 부분*/
	                .and()
	                .csrf().disable()
	                .formLogin()
	                .loginPage("/user/login")
	                .defaultSuccessUrl("/question/list")
	                
	                //로그아웃 영역
	                .and()
	                .logout()
	                .logoutRequestMatcher(new AntPathRequestMatcher("/user/logout"))
	                .logoutSuccessUrl("/user/login")
	                .invalidateHttpSession(true)
	        ;
	        return http.build();
	    }

	    //PasswordEncoder 빈(bean)
	    @Bean
	    public PasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	    }

	    /*AuthenticationManager 스프링 시큐리티의 인증을 담당*/
	    @Bean
	    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
	        return authenticationConfiguration.getAuthenticationManager();
	    }
	}
