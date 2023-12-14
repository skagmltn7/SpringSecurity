package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

	private String errorPage;

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
		// 발생한 인가예외 객체를 파라미터로 받아와 메시지를 쿼리스트링 형태로 넘겨준다
		String deniedUrl = errorPage + "?exception=" + accessDeniedException.getMessage();
		response.sendRedirect(deniedUrl);
	}

	public void setErrorPage(String errorPage) {
		this.errorPage = errorPage;
	}
}
