package io.security.corespringsecurity.security.common;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

public class AjaxLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
		// 인증을 받지 않은 사용자가 자원에 접근을 시도한 상황이기 때문에 401 에러 발생
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "UnAuthorized");
	}
}
