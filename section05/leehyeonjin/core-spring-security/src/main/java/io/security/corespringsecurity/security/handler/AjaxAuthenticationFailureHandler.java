package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

public class AjaxAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private ObjectMapper objectMapper = new ObjectMapper();

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
		String errorMessage = "Invalid Username or Password";

		// 클라이언트에 응답하기 위한 Http Status 값 및 MediaType 설정
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);

		// 예외 종류에 따라 예외 메시지 분기
		if (exception instanceof BadCredentialsException) {
			errorMessage = "Invalid Username or Password";
		} else if (exception instanceof DisabledException) {
			errorMessage = "Locked";
		} else if (exception instanceof CredentialsExpiredException) {
			errorMessage = "Expired password";
		}

		// 추출해둔 사용자 객체(Account)를 ObjectMapper를 통해 json 형식의 응답값으로 body에 담음
		objectMapper.writeValue(response.getWriter(), errorMessage);
	}
}
