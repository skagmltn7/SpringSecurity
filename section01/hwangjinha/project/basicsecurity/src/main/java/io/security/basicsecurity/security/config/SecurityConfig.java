package io.security.basicsecurity.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .anyRequest().authenticated();
//        http
//                .formLogin()
//                .loginPage("/loginPage")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("password")
//                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication" + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .and()
//                .logout()
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("logout");
//                        response.sendRedirect("/login");
//                    }
//                })
//                .and()
//                .rememberMe()
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService)
//        ;
//        =========================
//        동시 세션 제어
//        http
//                .sessionManagement()
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(false);
//                // true : 새로운 세션 생성을 막는다.
//                // false : 새로운 세션을 만들고 기존 세션을 만료시킨다. 다른 브라우저에서 실험할 수 있다.
//        세션공격 방지 : 공격자가 동일한 세션 id를 사용하면 피해자가 로그인 할 시 공격자가 로그인 한 것처럼 사용할 수 있는 것.
//        하나의 브라우저에서 두 개의 탭을 사용하는 것처럼
//        http
//                .sessionManagement()
//                .sessionFixation().changeSessionId();
//        세션 정책
//        http
//                .sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
//        SessionCreationPolicy.ALWAYS : 스프링 시큐리티가 항상 세션 생성
//        SessionCreationPolicy.IF_REQUIRED : 스프링 시큐리티가 필요 시 생성 (기본 값)
//        SessionCreationPolicy.STATELESS : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
//        SessionCreationPolicy.NEVER : 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음
//        =================================
//        세션 제어 필터 : 새로운 리퀘스트는 SessionManagementFilter, 이전 사용자의 리퀘스트가 ConcurrentSessionFilter에 들어간다??
//        http
//                .sessionManagement()
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(true);
//        ========================
//        권한 설정 - 설정 시 구체적인 경로가 먼저 오고 그것보다 큰 범위의 경로가 뒤에 오도록 해야 한다
//        표현식
//        authenticated() 인증된 사용자의 접근을 허용
//        익명 사용자, 기억하기, SpEL표현식의 평가 결에 따라, 주어진 역할이 있다면 등등의 조건을 줄 수 있다.
        http
                .authorizeRequests()
                .antMatchers("/login").permitAll()
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        http
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache();
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);
                    }
                });
//        =====================
//        인증/인가 API - ExceptionTranslationFilter : 예외 처리 및 요청 캐시 필터
//        AuthenticationException - 인증 예외 처리 : AuthenticationEntryPoint 호출 (로그인 페이지 이동, 401 오류 코드 전달 등
//        AccessDeniedException - 인가 예외 처리 : AccessDeniedHandler에서 예외 처리하도록 제공
        http
                .exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                });

//        =======================
//        Form 인증 - CSRF (사이트 간 요청 위조)
//        CsrfFilter - 모든 요청에 랜덤학 생성된 토큰을 HTTP 파라미터로 요구
//            요청 시 전달되는 토큰 값과 서버에 저장된 실제 값과 비교한 후 만약 일치하지 않으면 요청은 실패한다
        http
                .csrf().disable();

    }
}