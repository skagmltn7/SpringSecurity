package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.security.corespringsecurity.util.WebUtil;

@Component
public class FormAccessDeniedHandler implements AccessDeniedHandler {

	private String errorPage;
	private ObjectMapper objectMapper = new ObjectMapper();
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
		// 발생한 인가예외 객체를 파라미터로 받아와 메시지를 JSON 형태로 넘겨준다
		if (WebUtil.isAjax(request)) {
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.getWriter().write(this.objectMapper.writeValueAsString(ResponseEntity.status(HttpStatus.FORBIDDEN)));
		}

		// 발생한 인가예외 객체를 파라미터로 받아와 메시지를 쿼리스트링 형태로 넘겨준다
		else {
			String deniedUrl = errorPage + "?exception=" + accessDeniedException.getMessage();
			redirectStrategy.sendRedirect(request, response, deniedUrl);
		}
	}

	public void setErrorPage(String errorPage) {
		if ((errorPage != null) && !errorPage.startsWith("/")) {
			throw new IllegalArgumentException("errorPage must begin with '/'");
		}
		this.errorPage = errorPage;
	}
}
