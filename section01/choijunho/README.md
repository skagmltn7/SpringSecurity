# 01. 강의에서 다루는 내용, 개발환경, 선수지식

1. 스프링 시큐리티의 보안 설정 API 와 이와 연계된 각 Filter 들에 대해 학습한다

- 각 API 의 개념과 기본적인 사용법, API 처리 과정, API 동작방식 등 학습
- API 설정 시 생성 및 초기화 되어 사용자의 요청을 처리하는 Filter 학습

2. 스프링 시큐리티 내부 아키텍처와 각 객체의 역할 및 처리과정을 학습한다

- 초기화 과정, 인증 과정, 인가과정 등을 아키텍처적인 관점에서 학습

3. 실전 프로젝트

- 인증 기능 구현 – Form 방식, Ajax 인증 처리
- 인가 기능 구현 – DB 와 연동해서 권한 제어 시스템 구현

개발 환경

- JDK 1.8 이상
- DB - Postgres
- IDE – Intellij or STS

선수 지식

- Spring Boot
- Spring MVC
- Spring Data JPA
- Thymeleaf
- Postgres
- Lombok

# 02. 인증 API – 프로젝트 구성 및 의존성 추가

`pom.xml`

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

- 스프링 시큐리티의 의존성 추가 시 일어나는 일들

  - 서버가 기동되면 스프링 시큐리티의 초기화 작업 및 보안 설정이 이루어진다
  - 별도의 설정이나 구현을 하지 않아도 기본적인 웹 보안 기능이 현재 시스템에 연동되어 작동함
    1. 모든 요청은 인증이 되어야 자원에 접근이 가능하다
    2. 인증 방식은 폼 로그인 방식과 httpBasic 로그인 방식을 제공한다
    3. 기본 로그인 페이지 제공한다
    4. 기본 계정 한 개 제공한다 – username : user / password : 랜덤 문자열

- 문제점
  - 계정 추가, 권한 추가, DB 연동 등
  - 기본적인 보안 기능 외에 시스템에서 필요로 하는 더 세부적이고 추가적인 보안기능이 필요

# 02. 인증 API – 사용자 정의 보안 기능 구현

- SecurityConfiguration : 사용자 정의 보안 설정 클래스
- WebSecurityConfigurerAdapter : 스프링 시큐리티의 웹 보안 기능 초기화 및 설정
- HttpSecurity : 세부적인 보안 기능을 설정할 수 있는 API 제공

SecurityConfiguration → WebSecurityConfigurerAdapter → HttpSecurity → (인증 API, 인가 API)

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

@Override
protected void configure(HttpSecurity http) throws Exception {
	http
		.authorizeRequests()
		.anyRequest().authenticated()
	.and()
		.formLogin();
}
```

기본계정 설정 (`application.properties`)

```properties
spring.security.user.name=admin
spring.security.user.password=admin
```

# 03. 인증 API – HTTP Basic 인증, BasicAuthenticationFilter

- HTTP는 자체적인 인증 관련 기능을 제공하며 HTTP 표준에 정의된 가장 단순한 인증 기법이다
- 간단한 설정과 Stateless가 장점 - Session Cookie(JSESSIONID) 사용하지 않음
- 보호자원 접근시 서버가 클라이언트에게 401 Unauthorized 응답과 함께 WWW-Authenticate header를 기술해서 인증요구를 보냄
- Client는 ID:Password 값을 Base64로 Encoding한 문자열을 Authorization Header에 추가한 뒤 Server에게 Resource를 요청
  - Authorization: Basic cmVzdDpyZXN0
- ID, Password가 Base64로 Encoding되어 있어 ID, Password가 외부에 쉽게 노출되는 구조이기 때문에 SSL이나 TLS는 필수이다

```java
protected void configure(HttpSecurity http) throws Exception {
	http.httpBasic();
}
```

# 04. 인증 API – Form 인증

`http.formLogin() // Form 로그인 인증 기능이 작동함`

```java
protected void configure(HttpSecurity http) throws Exception {
	 http.formLogin()
            .loginPage("/login.html")   			// 사용자 정의 로그인 페이지
            .defaultSuccessUrl("/home")				// 로그인 성공 후 이동 페이지
            .failureUrl("/login.html?error=true")		// 로그인 실패 후 이동 페이지
            .usernameParameter("username")			// 아이디 파라미터명 설정
            .passwordParameter("password")			// 패스워드 파라미터명 설정
            .loginProcessingUrl("/login")			// 로그인 Form Action Url
            .successHandler(loginSuccessHandler())		// 로그인 성공 후 핸들러
            .failureHandler(loginFailureHandler())		// 로그인 실패 후 핸들러
}
```

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin()
                //.loginPage("/loginPage")
                //.defaultSuccessUrl("/")
                //.failureUrl("/login")
                .usernameParameter("userid")
                .passwordParameter("userpw")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("Authentication:" + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                            System.out.println("Authentication:" + exception.getMessage());
                        response.sendRedirect("/");
                    }
                })
                .permitAll()
                ;
    }
}
```

# 05. 인증 API – UsernamePasswordAuthenticationFilter

# 06. 인증 API – Logout, LogoutFilter

`http.logout() // 로그아웃 기능이 작동함`

```java
protected void configure(HttpSecurity http) throws Exception {
	 http.logout()						// 로그아웃 처리
            .logoutUrl("/logout")				// 로그아웃 처리 URL
            .logoutSuccessUrl("/login")			// 로그아웃 성공 후 이동페이지
            .deleteCookies("JSESSIONID", "remember-me") 	// 로그아웃 후 쿠키 삭제
            .addLogoutHandler(logoutHandler())		        // 로그아웃 핸들러
            .logoutSuccessHandler(logoutSuccessHandler()) 	// 로그아웃 성공 후 핸들러
}
```

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin()
                //.loginPage("/loginPage")
                //.defaultSuccessUrl("/")
                //.failureUrl("/login")
                .usernameParameter("userid")
                .passwordParameter("userpw")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("Authentication:" + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("Authentication:" + exception.getMessage());
                        response.sendRedirect("/");
                    }
                })
                .permitAll()


                .and()

                .logout()
                //.logoutUrl("/logout")
                //.logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me")
                ;
    }
}
```

# 07. 인증 API – Remember Me 인증

1. 세션이 만료되고 웹 브라우저가 종료된 후에도 어플리케이션이 사용자를 기억하는 기능

2. Remember-Me 쿠키에 대한 Http 요청 을 확인한 후 토큰 기반 인증을 사용해 유효성을 검사하고 토큰이 검증되면 사용자는 로그인 된다

3. 사용자 라이프 사이클
   - 인증 성공(Remember-Me쿠키 설정)
   - 인증 실패(쿠키가 존재하면 쿠키 무효화)
   - 로그아웃(쿠키가 존재하면 쿠키 무효화)

`http.rememberMe() // rememberMe 기능이 작동함`

```java
protected void configure(HttpSecurity http) throws Exception {
        http.rememberMe()
        .rememberMeParameter("remember")        // 기본 파라미터명은 remember-me
        .tokenValiditySeconds(3600)             // Default 는 14일
        .alwaysRemember(true)                   // 리멤버 미 기능이 활성화되지 않아도 항상 실행 (일반적으로 False)
        .userDetailsService(userDetailsService)
}
```

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin()
                //.loginPage("/loginPage")
                //.defaultSuccessUrl("/")
                //.failureUrl("/login")
                .usernameParameter("userid")
                .passwordParameter("userpw")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("Authentication:" + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("Authentication:" + exception.getMessage());
                        response.sendRedirect("/");
                    }
                })
                .permitAll()


                .and()


                .logout()
                //.logoutUrl("/logout")
                //.logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me")


                .and()


                .rememberMe()
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600)
                .userDetailsService(userDetailsService);
        ;
    }
}
```

# 08. 인증 API – RememberMeAuthenticationFilter

# 09. 인증 API – AnonymousAuthenticationFilter

인증을 받지않은 사용자를 별도의 익명사용자용 필터를 사용하여 관리한다.

- 익명사용자 인증 처리 필터
- 익명사용자와 인증 사용자를 구분해서 처리하기 위한 용도로 사용
- 화면에서 인증 여부를 구현할 때 isAnonymous() 와 isAuthenticated() 로 구분해서 사용
- 인증객체를 세션에 저장하지 않는다

# 10. 인증 API – 동시 세션 제어 / 세션 고정 보호 / 세션 정책

> 동시 세션 제어

동일한 계정으로 인증을 받을 때 생성되는 세션의 허용되는 개수가 제한되어 초과되었을 때 세션을 유지를 어떻게 할까?

1. 이전 사용자 세션 만료
2. 현재 사용자 인증 실패

`http.sessionManagement() // 세션 관리 기능이 작동함`

```java
protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement()
        .maximumSessions(1)                     // 최대 허용 가능 세션 수 , -1 : 무제한 로그인 세션 허용
        .maxSessionsPreventsLogin(true)         // 동시 로그인 차단함,  false : 기존 세션 만료(default)
        .invalidSessionUrl("/invalid")          // 세션이 유효하지 않을 때 이동 할 페이지
        .expiredUrl("/expired ")  	        // 세션이 만료된 경우 이동 할 페이지
        }
```

> 세션 고정 보호

`http.sessionManagement() // 세션 관리 기능이 작동함`

```java
protected void configure(HttpSecurity http) throws Exception {
	http.sessionManagement()
                .sessionFixation().changeSessionId() // 기본값
                // changeSessionId, none, migrateSession, newSession
                // changeSessionID  : 세션 고정 공격 보호 | 이전 속성 그대로 사용 (Servlet 3.1 이상)
                // none : 세션 고정 공격 가능
                // migrateSession   : 세션 고정 공격 보호 | 이전 속성 그대로 사용 (Servlet 3.1 이하)
                // newSession       : 세션 고정 공격 보호 | 이전 속성 새로 생성
}
```

> 세션 정책

`http.sessionManagement() // 세션 관리 기능이 작동함`

```java
protected void configure(HttpSecurity http) throws Exception {
    http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy. If_Required )
}
```

- SessionCreationPolicy. Always : 스프링 시큐리티가 항상 세션 생성
- SessionCreationPolicy. If_Required : 스프링 시큐리티가 필요 시 생성(기본값)
- SessionCreationPolicy. Never : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
- SessionCreationPolicy. Stateless : 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음

# 11. 인증 API – SessionManagementFilter ConcurrentSessionFilter

> SessionManagementFilter

- 세션 관리

  - 인증 시 사용자의 세션정보를 등록, 조회, 삭제 등의 세션 이력을 관리

- 동시적 세션 제어

  - 동일 계정으로 접속이 허용되는 최대 세션수를 제한

- 세션 고정 보호

  - 인증 할 때마다 세션쿠키를 새로 발급하여 공격자의 쿠키 조작을 방지

- 세션 생성 정책
  - Always, If_Required, Never, Stateless

> ConcurrentSessionFilter

- 매 요청 마다 현재 사용자의 세션 만료 여부 체크
- 세션이 만료로 설정되었을 경우 즉시 만료 처리
- session.isExpired() == true ("This session has been expired")
  - 로그아웃 처리
  - 즉시 오류 페이지 응답

> SessionManagementFilter & ConcurrentSessionFilter

1. 새 사용자가 동일한 계정으로 로그인
2. SessionManagementFilter가 최대 세선 허용 개수 확인 후 초과시 만료시킴
3. ConcurrentSessionFilter가 이전 사용자가 이전 세션으로 로그인 시 로그아웃시키고 만료

# 12. 인가 API – 권한 설정 및 표현식

- 선언적 방식

  - URL
    - `http.antMatchers("/users/**").hasRole("USER")`
  - Method
    - `@PreAuthorize("hasRole('USER’)")`
    - `public void user(){ System.out.println("user")}`

- 동적 방식 – DB 연동 프로그래밍
  - URL
  - Method

```java

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
        .antMatcher("/shop/**")
        .authorizeRequests()
        .antMatchers("/shop/login", "/shop/users/**").permitAll()
        .antMatchers("/shop/mypage").hasRole("USER")
        .antMatchers("/shop/admin/pay").access("hasRole('ADMIN')")
        .antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
        .anyRequest().authenticated()
}
```

※ **주의 사항 - 설정 시 구체적인 경로가 먼저 오고 그것 보다 큰 범위의 경로가 뒤에 오도록 해야 한다**

| 메소드                     | 동작                                                     |
| -------------------------- | -------------------------------------------------------- |
| authenticated()            | 인증된 사용자의 접근을 허용                              |
| fullyAuthenticated()       | 인증된 사용자의 접근을 허용,rememberMe 인증 제외         |
| permitAll()                | 무조건 접근을 허용                                       |
| denyAll()                  | 무조건 접근을 허용하지 않음                              |
| anonymous()                | 익명사용자의 접근을 허용                                 |
| rememberMe()               | 기억하기를 통해 인증된 사용자의 접근을 허용              |
| access(String)             | 주어진 SpEL표현식의 평가 결과가 true이면 접근을 허용     |
| hasRole(String)            | 사용자가 주어진 역할이 있다면 접근을 허용                |
| hasAuthority(String)       | 사용자가 주어진 권한이 있다면                            |
| hasAnyRole(String...)      | 사용자가 주어진 권한이 있다면 접근을 허용                |
| hasAnyAuthority(String...) | 사용자가 주어진 권한 중 어떤 것이라도 있다면 접근을 허용 |
| hasIpAddress(String)       | 주어진 IP로부터 요청이 왔다면 접근을 허용                |

```java
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
    auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
    auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");
}
```

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            .authorizeRequests()
            .antMatchers("/user").hasRole("USER")
            .antMatchers("/admin/pay").hasRole("ADMIN")
            .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
            .anyRequest().authenticated();
}
```

# 14. 인증/인가 API – ExceptionTranslationFilter & RequestCacheAwareFilter

> ExceptionTranslationFilter

- AuthenticationException

  - 인증 예외 처리

    1. AuthenticationEntryPoint 호출

       - 로그인 페이지 이동, 401 오류 코드 전달 등

    2. 인증 예외가 발생하기 전의 요청 정보를 저장
       - RequestCache - 사용자의 이전 요청 정보을 세션에 저장하고 이를 꺼내 오는 캐시 메카니즘
       - SavedRequest - 사용자가 요청했던 request 파라미터 값들, 그 당시의 헤더값들 등이 저장

- AccessDeniedException
  - 인가 예외 처리
    - AccessDeniedHandler 에서 예외 처리하도록 제공

`http. exceptionHandling() // 예외처리 기능이 작동함`

```java
protected void configure(HttpSecurity http) throws Exception {
	 http.exceptionHandling()
		.authenticationEntryPoint(authenticationEntryPoint())     	// 인증 실패 시 처리
		.accessDeniedHandler(accessDeniedHandler()) 			// 인가 실패 시 처리
}
```

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
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
        })

        http
        .exceptionHandling()
        .authenticationEntryPoint(new AuthenticationEntryPoint() {
            @Override
            public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                    response.sendRedirect("/login");
            }
        })
        .accessDeniedHandler(new AccessDeniedHandler() {
            @Override
            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                response.sendRedirect("/denied");
            }
        })
        ;
}
```

# 12. Form 인증 – CSRF, CsrfFilter

> CsrfFilter

- 모든 요청에 랜덤하게 생성된 토큰을 HTTP 파라미터로 요구
- 요청 시 전달되는 토큰 값과 서버에 저장된 실제 값과 비교한 후 만약 일치하지 않으면 요청은 실패한다

- Client

  - `<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />`
  - HTTP 메소드 : PATCH, POST, PUT, DELETE

- Spring Security
  - http.csrf() : 기본 활성화되어 있음
  - http.csrf().disabled() : 비활성화

```java

@Override
protected void configure(HttpSecurity http) throws Exception{
        http
        //.csrf().disable();
        .csrf();
}
```
