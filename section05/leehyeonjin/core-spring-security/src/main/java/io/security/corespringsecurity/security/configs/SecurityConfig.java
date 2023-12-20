package io.security.corespringsecurity.security.configs;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetailsSource;
import io.security.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.security.corespringsecurity.security.filter.PermitAllFilter;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.handler.FormAccessDeniedHandler;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadatsSource;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import io.security.corespringsecurity.security.provider.FormAuthenticationProvider;
import io.security.corespringsecurity.security.voter.IpAddressVoter;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final FormWebAuthenticationDetailsSource formWebAuthenticationDetailsSource;
	private final AuthenticationSuccessHandler formAuthenticationSuccessHandler;
	private final AuthenticationFailureHandler formAuthenticationFailureHandler;
	private final UserDetailsService userDetailsService;
	private final AuthenticationConfiguration authenticationConfiguration;
	private final SecurityResourceService securityResourceService;
	private String[] permitAllResources = {"/", "/login", "/user/login/**"};

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		// 정적 자원(css/js/image)들이 보안필터를 거치지 않도록 설정
		return (web) -> web
			.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		// 생성해둔 커스텀 Provider 클래스를 빈으로 등록하여 인증시 시큐리티가 사용할 수 있도록 함
		return new FormAuthenticationProvider(userDetailsService, passwordEncoder());
	}

	@Bean
	public AuthenticationProvider ajaxAuthenticationProvider() {
		// 생성해둔 커스텀 Provider 클래스를 빈으로 등록하여 인증시 시큐리티가 사용할 수 있도록 함
		return new AjaxAuthenticationProvider(userDetailsService, passwordEncoder());
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		// AuthenticationManager 빈 생성 시 스프링의 내부 동작으로 인해 위에서 작성한 UserSecurityService와 PasswordEncoder가 자동으로 설정
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		// PasswordEncoder를 생성하여 스프링 빈으로 등록
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public AjaxAuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
		return new AjaxAuthenticationSuccessHandler();
	}

	@Bean
	public AjaxAuthenticationFailureHandler ajaxAuthenticationFailureHandler() {
		return new AjaxAuthenticationFailureHandler();
	}

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		// AccessDeniedHandler 객체를 생성하고, errorPage를 setter를 통해 설정한 후, 빈으로 등록
		FormAccessDeniedHandler accessDeniedHandler = new FormAccessDeniedHandler();
		accessDeniedHandler.setErrorPage("/denied");
		return accessDeniedHandler;
	}

	@Bean
	public PermitAllFilter customFilterSecurityInterceptor() throws Exception {
		// 필터를 추가하여 인가정보를 DB에 동적으로 바인딩할 수 있도록 하는 클래스를 설정
		PermitAllFilter permitAllFilter = new PermitAllFilter(permitAllResources);
		permitAllFilter.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
		permitAllFilter.setAccessDecisionManager(affirmativeBased());
		permitAllFilter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
		return permitAllFilter;
	}

	@Bean
	public UrlFilterInvocationSecurityMetadatsSource urlFilterInvocationSecurityMetadataSource() throws Exception {
		// url 방식으로 인가정보를 DB와 동적으로 바인딩하는 설정 빈등록
		return new UrlFilterInvocationSecurityMetadatsSource(urlResourcesMapFactoryBean().getObject(), securityResourceService);
	}

	private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
		UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
		urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
		return urlResourcesMapFactoryBean;
	}

	private AccessDecisionManager affirmativeBased() {
		// 하나만 승인되어도 인가를 승인해주는 AccessManager 빈등록
		AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecistionVoters());
		return affirmativeBased;
	}

	private List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
		// 설정한 인가정보를 리스트로 등록해주는 권한 Voter 빈등록
		List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();
		// IP주소 심의 관리자가 가장 먼저 추가되어 심사를 거쳐야 함(다른 voter가 우선 작동할 경우, 허용시 바로 자원에 접근이 되어버리기 때문)
		accessDecisionVoters.add(new IpAddressVoter(securityResourceService));
		accessDecisionVoters.add(roleVoter());
		return accessDecisionVoters;
	}

	@Bean
	public AccessDecisionVoter<? extends Object> roleVoter() {
		RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());
		return roleHierarchyVoter;
	}

	@Bean
	public RoleHierarchyImpl roleHierarchy() {
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		return roleHierarchy;
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// 특정 자원에 제한없이 모든 자원에 대한 접근시도시 인증이 필요
			.authorizeRequests()
			// .anyRequest().authenticated()

			.and()
			// DB의 인가 데이터와 스프링 시큐리티 설정을 동적으로 바인딩하는 필터 등록
			.addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class)

			// 인가예외에 대한 후속처리 설정
			.exceptionHandling()
			.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
			.accessDeniedPage("/denied")
			.accessDeniedHandler(accessDeniedHandler())

			// 기본적인 인증방식은 form login 방식
			.and()
			.formLogin()
			.loginPage("/login") // 커스텀 로그인 페이지로 연결
			.loginProcessingUrl("/login_proc") // 커스텀 로그인 페이지의 form 태그에 설정해둔 action과 일치시킴
			.authenticationDetailsSource(formWebAuthenticationDetailsSource) // 로그인시 id,pw 이외의 부가정보를 저장하기 위한 클래스
			.successHandler(formAuthenticationSuccessHandler) // 로그인 성공시 수행할 로직 등록
			.failureHandler(formAuthenticationFailureHandler) // 로그인 실패시 수행할 로직 등록
			.permitAll();

		// Ajax(비동기) 방식의 요청을 받기 위해 csrf 설정 무효화
		http.csrf().disable();

		// DSLs 방식으로 설정된 시큐리티 설정 적용
		customConfigurer(http);

		return http.build();
	}

	private void customConfigurer(HttpSecurity http) throws Exception {
		http
			.apply(new AjaxLoginConfigurer<>())
			.successHandlerAjax(ajaxAuthenticationSuccessHandler())
			.failureHandlerAjax(ajaxAuthenticationFailureHandler())
			.loginProcessingUrl("/api/login")
			.setAuthenticationManager(authenticationManager(authenticationConfiguration));
	}
}
