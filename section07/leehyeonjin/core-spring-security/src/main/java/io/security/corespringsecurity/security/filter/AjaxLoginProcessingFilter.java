package io.security.corespringsecurity.security.filter;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.security.corespringsecurity.domain.dto.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import io.security.corespringsecurity.util.WebUtil;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

	private ObjectMapper objectMapper = new ObjectMapper();

	public AjaxLoginProcessingFilter() {
		// 특정 url이 요청되었을 때만 현재 필터를 작동할 수 있도록 설정
		super(new AntPathRequestMatcher("/ajaxLogin", "POST"));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
		// 현재 요청이 Ajax 요청인지 확인하여 Ajax 요청이 아니라면 예외처리
		if (!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
			throw new IllegalArgumentException("Authentication method not supported");
		}

		// json 방식으로 전달된 사용자 입력 정보(비동기 방식이기 때문)을 ObjectMapper를 이용하여 필요한 타입(Account)으로 변환
		AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

		// 추출한 사용자 입력 정보 중 인증에 필요한 데이터가 null인 경우, 예외처리
		if (StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
			throw new AuthenticationServiceException("Username or Password is not provided");
		}

		// 사용자가 로그인시 입력한 정보(id,pw)를 가져와 Ajax용 인증 객체 생성
		AjaxAuthenticationToken token = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());

		// AuthenticationManager에 생성한 토큰 전달
		return getAuthenticationManager().authenticate(token);
	}
}
