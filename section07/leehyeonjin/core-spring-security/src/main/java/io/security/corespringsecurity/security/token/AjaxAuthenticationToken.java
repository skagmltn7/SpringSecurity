package io.security.corespringsecurity.security.token;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class AjaxAuthenticationToken extends AbstractAuthenticationToken {

	private final Object principal;
	private Object credentials;

	// 실제 인증을 받기 전(AuthenticationManager 거치기 전) 사용자가 입력한 인증에 필요한 데이터를 담고있음
	public AjaxAuthenticationToken(Object principal, Object credentials) {
		super(null);
		this.principal = principal;
		this.credentials = credentials;
		setAuthenticated(false);
	}

	// 실제 인증이 모두 완료된 후(통과) 애플리케이션 전역에서 사용될 수 있도록 SecurityContext에 저장되는 토큰
	public AjaxAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		super.setAuthenticated(true);
	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}
}
