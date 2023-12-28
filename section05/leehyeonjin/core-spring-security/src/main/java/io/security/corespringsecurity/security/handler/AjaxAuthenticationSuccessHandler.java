package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.security.corespringsecurity.domain.entity.Account;

public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private ObjectMapper objectMapper = new ObjectMapper();

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		// Ajax용 provider에서 최종 인증 성공시 담아둔 사용자 객체(Account)를 추출
		Account account = (Account)authentication.getPrincipal();

		// 클라이언트에 응답하기 위한 Http Status 값 및 MediaType 설정
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);

		// 추출해둔 사용자 객체(Account)를 ObjectMapper를 통해 json 형식의 응답값으로 body에 담음
		objectMapper.writeValue(response.getWriter(), account);
	}
}
