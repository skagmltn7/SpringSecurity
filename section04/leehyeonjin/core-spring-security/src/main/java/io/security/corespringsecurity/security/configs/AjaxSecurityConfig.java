package io.security.corespringsecurity.security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import io.security.corespringsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.handler.AjaxAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class AjaxSecurityConfig {

	private final UserDetailsService userDetailsService;
	private final AuthenticationConfiguration authenticationConfiguration;

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		// Ajax용 AccessDeniedHandler 빈등록
		return new AjaxAccessDeniedHandler();
	}

	@Bean
	public AuthenticationSuccessHandler authenticationSuccessHandler() {
		// Ajax용 AuthenticationSuccessHandler 빈등록
		return new AjaxAuthenticationSuccessHandler();
	}

	@Bean
	public AuthenticationFailureHandler authenticationFailureHandler() {
		// Ajax용 AuthenticationFailureHandler 빈등록
		return new AjaxAuthenticationFailureHandler();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		// AuthenticationManager 빈 생성 시 스프링의 내부 동작으로 인해 위에서 작성한 UserSecurityService와 PasswordEncoder가 자동으로 설정
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		// 생성해둔 커스텀 Provider 클래스를 빈으로 등록하여 인증시 시큐리티가 사용할 수 있도록 한인
		return new AjaxAuthenticationProvider(userDetailsService, passwordEncoder());
	}

	@Bean
	public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
		// Ajax용 필터 커스텀 및 해당 필터에 사용되는 Manager, Handler 등록
		AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
		ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
		ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
		ajaxLoginProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
		return ajaxLoginProcessingFilter;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		// PasswordEncoder를 생성하여 스프링 빈으로 등록
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// 특정한 URL(자원)에 대해서만 해당 필터가 작동하도록 제한
			.antMatcher("/api/**")
			.authorizeRequests()
			.antMatchers("/api/messages").hasRole("MANAGER")
			.anyRequest().authenticated()

			// Ajax용 인증 필터를 스프링 시큐리티 필터체인에 추가 등록
			.and()
			.addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

		http
			// Ajax 용 인증/인가 예외처리(401, 403) 핸들러 등록
			.exceptionHandling()
			.authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
			.accessDeniedHandler(accessDeniedHandler());

		http
			// Ajax Request 테스트시에 해당 기능으로 인한 오류방지
			.csrf().disable();

		/** custom DSLs 로 스프링 시큐리티 설정 커스텀
		customConfigureAjax(http);*/

		return http.build();
	}

	/** DSLs 로 스프링 시큐리티의 설정을 대체할 수 있음
	private void customConfigureAjax(HttpSecurity http) throws Exception {
		http
			// DSLs 를 통해 구현해둔 커스텀 Configurer를 등록
			.apply(new AjaxLoginConfigurer<>())
			.successHandlerAjax(authenticationSuccessHandler())
			.failureHandlerAjax(authenticationFailureHandler())
			.setAuthenticationManager(authenticationManager(authenticationConfiguration))
			.loginProcessingUrl("/api/login");
	}*/
}
