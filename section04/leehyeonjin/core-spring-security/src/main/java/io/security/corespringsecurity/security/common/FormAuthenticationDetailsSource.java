package io.security.corespringsecurity.security.common;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Component
public class FormAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {

	@Override
	public WebAuthenticationDetails buildDetails(HttpServletRequest context) {
		// 커스텀 해둔 WebAuthenticationDetails 객체를 생성하며, 파라미터로 Request 객체 전달
		return new FormWebAuthenticationDetails(context);
	}
}
