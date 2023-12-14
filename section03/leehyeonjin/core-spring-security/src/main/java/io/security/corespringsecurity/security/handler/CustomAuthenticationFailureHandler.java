package io.security.corespringsecurity.security.handler;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
		// 클라이언트 화면에 인증 실패 경우에 따라 발생하는 예외에 대한 메시지를 제공
		String errorMessage = "Invalid Username or Password";

		// 비밀번호가 일치하지 않는 경우
		if (exception instanceof BadCredentialsException) {
			errorMessage = "Invalid Username or Password";
		}
		// secret key(details)가 일치하지 않는 경우
		else if (exception instanceof InsufficientAuthenticationException) {
			errorMessage = "Invalid Secret Key";
		}

		// 인증실패시 요청할 url에 쿼리스트링을 이용하여 예외 전달
		setDefaultFailureUrl("/login?error=true&exception=" + errorMessage);

		super.onAuthenticationFailure(request, response, exception);
	}
}
