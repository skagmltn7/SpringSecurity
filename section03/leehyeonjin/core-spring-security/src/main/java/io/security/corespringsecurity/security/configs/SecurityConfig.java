package io.security.corespringsecurity.security.configs;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
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
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final UserDetailsService userDetailsService;
	private final AuthenticationDetailsSource authenticationDetailsSource;
	private final AuthenticationSuccessHandler authenticationSuccessHandler;
	private final AuthenticationFailureHandler authenticationFailureHandler;

	/** 메모리 방식으로 등록했던 사용자 방식 -> 데이터베이스 저장 사용자로 변경
	@Bean
	public UserDetailsService userDetailsService() {
		// PasswordEncoder를 통해 패스워드를 암호화하여 저장
		String password = passwordEncoder().encode("1111");

		// 각각 권한설정을 해 줄 사용자를 인메모리 방식으로 생성하여 스프링 빈으로 등록
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withUsername("user").password(password).roles("USER").build());
		manager.createUser(User.withUsername("manager").password(password).roles("MANAGER", "USER").build());
		manager.createUser(User.withUsername("ADMIN").password(password).roles("ADMIN", "USER", "MANAGER").build());

		return manager;
	}**/

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		// AuthenticationManager 빈 생성 시 스프링의 내부 동작으로 인해 위에서 작성한 UserSecurityService와 PasswordEncoder가 자동으로 설정
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		// 생성해둔 커스텀 Provider 클래스를 빈으로 등록하여 인증시 시큐리티가 사용할 수 있도록 한인
		return new CustomAuthenticationProvider(userDetailsService, passwordEncoder());
	}

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		// AccessDeniedHandler 객체를 생성하고, errorPage를 setter를 통해 설정한 후, 빈으로 등록
		CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
		accessDeniedHandler.setErrorPage("denied");
		return accessDeniedHandler;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		// PasswordEncoder를 생성하여 스프링 빈으로 등록
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		// 정적 자원(css/js/image)들이 보안필터를 거치지 않도록 설정
		return (web) -> web
			.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			// 특정 자원에 제한없이 모든 자원에 대한 접근시도시 인증이 필요
			.authorizeRequests()
			.antMatchers("/", "/users", "/login/**", "/login*").permitAll() // 루트(/) 페이지에는 모두 접근허용
			.antMatchers("/mypage").hasRole("USER") // 마이페이지에는 USER 권한의 사용자만 접근가능
			.antMatchers("/messages").hasRole("MANAGER") // 메시지에는 MANAGER 권한의 사용자만 접근가능
			.antMatchers("/config").hasRole("ADMIN") // 설정에는 ADMIN 권한의 사용자만 접근가능
			.anyRequest().authenticated()

			// 인가예외에 대한 후속처리 설정
			.and()
			.exceptionHandling()
			.accessDeniedHandler(accessDeniedHandler())

			// 기본적인 인증방식은 form login 방식
			.and()
			.formLogin()
			.loginPage("/login") // 커스텀 로그인 페이지로 연결
			.loginProcessingUrl("/login_proc") // 커스텀 로그인 페이지의 form 태그에 설정해둔 action과 일치시킴
			.authenticationDetailsSource(authenticationDetailsSource) // 로그인시 id,pw 이외의 부가정보를 저장하기 위한 클래스
			.successHandler(authenticationSuccessHandler) // 로그인 성공시 수행할 로직 등록
			.failureHandler(authenticationFailureHandler) // 로그인 실패시 수행할 로직 등록
			.permitAll();

		return http.build();
	}
}
