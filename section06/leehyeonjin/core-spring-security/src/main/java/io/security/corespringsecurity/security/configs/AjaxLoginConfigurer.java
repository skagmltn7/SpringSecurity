package io.security.corespringsecurity.security.configs;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;

public final class AjaxLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
	AbstractAuthenticationFilterConfigurer<H, AjaxLoginConfigurer<H>, AjaxLoginProcessingFilter> {

	private AuthenticationSuccessHandler successHandler;
	private AuthenticationFailureHandler failureHandler;
	private AuthenticationManager authenticationManager;

	public AjaxLoginConfigurer() {
		// 인증 filter를 생성하여 부모 생성자로 주입
		super(new AjaxLoginProcessingFilter(), null);
	}

	@Override
	public void init(H http) throws Exception {
		super.init(http);
	}

	@Override
	public void configure(H http) throws Exception {
		// getSharedObject() : 공유객체를 가져옴
		if (authenticationManager == null) {
			authenticationManager = http.getSharedObject(AuthenticationManager.class);
		}

		// 인증 filter 정의 : manager, handler 등록
		getAuthenticationFilter().setAuthenticationManager(authenticationManager);
		getAuthenticationFilter().setAuthenticationSuccessHandler(successHandler);
		getAuthenticationFilter().setAuthenticationFailureHandler(failureHandler);

		// 인증 받을때 필요한 다양한 설정 등록 : session 전략, remember me
		SessionAuthenticationStrategy sessionAuthenticationStrategy = http.getSharedObject(SessionAuthenticationStrategy.class);
		if (sessionAuthenticationStrategy != null) {
			getAuthenticationFilter().setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
		}
		RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
		if (rememberMeServices != null) {
			getAuthenticationFilter().setRememberMeServices(rememberMeServices);
		}

		// setSharedObject() : 공유객체를 저장함
		http.setSharedObject(AjaxLoginProcessingFilter.class, getAuthenticationFilter());

		// 커스텀한 필터를 스프링 시큐리티 필터체인에 등록
		http.addFilterBefore(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	}

	public AjaxLoginConfigurer<H> successHandlerAjax(AuthenticationSuccessHandler successHandler) {
		this.successHandler = successHandler;
		return this;
	}

	public AjaxLoginConfigurer<H> failureHandlerAjax(AuthenticationFailureHandler failureHandler) {
		this.failureHandler = failureHandler;
		return this;
	}

	public AjaxLoginConfigurer<H> setAuthenticationManager(AuthenticationManager manager) {
		this.authenticationManager = manager;
		return this;
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		// RequestMatcher 클래스에 login 처리용 request method 전달
		return new AntPathRequestMatcher(loginProcessingUrl, "POST");
	}
}
