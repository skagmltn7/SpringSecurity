package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class FormAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	// 이전에 사용자가 가고자했던 페이지의 url을 담고 있는 캐시 주입
	private RequestCache requestCache = new HttpSessionRequestCache();

	// 최종적으로 이동할 수 있도록 리다이렉트 객체 주입
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		// 인증에 성공하기 전 요청했던 url 정보가 없을 경우 사용할 디폴트 url 설정
		setDefaultTargetUrl("/");

		// 인증에 성공하기 전에 사용자가 요청했던 정보 추출
		SavedRequest savedRequest = requestCache.getRequest(request, response);

		// 인증에 성공하기 전 요청했던 url 정보가 있는 경우 해당 url로 이동
		if (savedRequest != null) {
			String targetUrl = savedRequest.getRedirectUrl();
			redirectStrategy.sendRedirect(request, response, targetUrl);
		}

		// 인증에 성공하기 전 요청했던 url 정보가 없는 경우 기본 url로 이동
		else {
			redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
		}
	}
}
