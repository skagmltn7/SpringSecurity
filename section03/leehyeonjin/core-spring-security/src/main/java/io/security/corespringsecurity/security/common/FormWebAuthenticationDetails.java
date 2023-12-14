package io.security.corespringsecurity.security.common;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

	// 사용자가 로그인시 입력할 id, pw 제외한 부가정보
	private String secretKey;

	public FormWebAuthenticationDetails(HttpServletRequest request) {
		super(request);
		// 요청 정보로부터 부가정보를 추출한다
		secretKey = request.getParameter("secret_key");
	}

	public String getSecretKey() {
		return secretKey;
	}
}
