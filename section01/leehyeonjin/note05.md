# spring security 기본 api 및 filter 이해( 예외, CSRF )

---

### 13. 인증/인가 API - ExceptionTranslationFilter, RequestCacheAwareFilter

**ExeptionTranslationFilter**

- ExceptionTranslationFilter는 자신의 뒤에 위치한 FilterSecurityInterceptor를 try~catch문으로 감싸서 호출한다.
- 이때 FilterSecurityInterceptor에서 인증/인가 예외가 발생하여 catch문에 걸린다면 ExceptionTranslationFilter는 곧바로 인증/인가 인지여부에 따라 아래 예외를 발생시킨다.

<img width="693" alt="Untitled (13)" src="https://github.com/hgene0929/hgene0929/assets/90823532/a35a1bf9-1184-42f3-839e-03f16e4ae0d8">

1. `AuthenticationException` : 인증 예외 처리.
    1. AuthenticationEntryPoint 구현체 호출 : 로그인 페이지 이동, 401 오류 코드 전달 등.
    2. 인증 예외가 발생하기 전의 요청 정보를 저장 : RequestCache - 사용자가 이전 요청 정보를 세션에 저장하고 이를 꺼내오는 캐시 매커니즘.
    - SavedRequest : 사용자가 요청했던 request 파라미터 값들, 그 당시의 헤더값들 등이 저장.
2. `AccessDeniedException` : 인가 예외 처리.
    1. AccessDeniedHandler에서 예외 처리하도록 제공.

   > 사실상 인증을 받지 않은 모든 사용자는 익명 사용자이기 때문에 인가예외로 처음에는 이동하지만, 스프링 시큐리티는 익명사용자로 인해 발생하는 인가 예외처리를 AuthenticationException으로 전달하여 처리하기 때문에 인증예외가 발생하는 것이다.
>

- 예외처리 API :

```java
@Configuration
@EnableWebSecurity //웹보안 활성화를 위한 애노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	UserDetailsService userDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.formLogin()
				.successHandler(new AuthenticationSuccessHandler() {
					@Override
					public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
						RequestCache requestCache = new HttpSessionRequestCache(); //이전에 사용자가 인증실패했을때의 정보( 가고자 했던 페이지 등 )를 저장하고 있는 캐시
						SavedRequest savedRequest = requestCache.getRequest(request, response); //원래 사용자가 가고자했던 요청 정보
						String redirectUrl = savedRequest.getRedirectUrl();
						response.sendRedirect(redirectUrl); //이전에 인증에 실패한 사용자가 가고자 했던 이동 요청 정보를 세션에 캐싱해둔 것을 활용하여 계속 이어서 진행할 수 있도록 처리
					}
				});
		http
			.exceptionHandling() //예외처리 기능이 작동함
			.authenticationEntryPoint(new AuthenticationEntryPoint() { //인증실패시 처리( AuthenticationEntryPoint의 commence()를 구현함으로써 처리 )
				@Override
				public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
					response.sendRedirect("/login");
				}
			})
			.accessDeniedHandler(new AccessDeniedHandler() { //인가실패시 처리
				@Override
				public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
					response.sendRedirect("/denied");
				}
			});
	}

}
```

### 14. Form 인증 - CSRF, CsrfFilter

**CSRF( 사이트 간 요청 위조 )**

<img width="523" alt="Untitled (14)" src="https://github.com/hgene0929/hgene0929/assets/90823532/639e25d0-b641-40a2-a8d2-9f591244539e">

- 공격자가 만든 링크에는 사용자가 계정을 가지고 있는 사이트(쇼핑몰)의 주소(URL)에 파라미터를 전달하도록 유도하는 구성으로 이루어져있다.
- 사용자가 이미 인증을 받아 쿠키까지 발급을 받은 상태라면, 쇼핑몰은 해당 사용자의 브라우저를 신뢰하기 때문에 사용자의 브라우저가 보내는 모든 요청을 정상적인 요청이라고 판단하고 동작한다.
- 이처럼 공격자의 의도에 따라 동작하도록 유도되어 공격을 받는 것을 CSRF라고 한다.

---

**CsrfFilter**

- 모든 요청에 랜덤하게 생성된 토큰을 HTTP 파라미터로 요구.
- 요청시 전달되는 토큰값과 서버에 저장된 실제값과 비교한 후, 만약 일치하지 않으면 요청 실패.
    - thymeleaf 와 같은 템플릿은 csrf 토큰을 form 태그에서 전송할 때 자동으로 바인딩해서 보내지만, jsp 등 일반적인 뷰 방식을 사용할 경우 직접 토큰을 함께 바인딩해주어야 한다.
- csrf API :

```java
@Configuration
@EnableWebSecurity //웹보안 활성화를 위한 애노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	UserDetailsService userDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable(); //csrf는 스프링 시큐리티의 default, 사용하지 않을 경우 disable() 처리만 해주면 된다
	}

}
```
