# spring security 기본 api 및 filter 이해( FormLogin, Logout )

---

### 01. 인증 API - 스프링 시큐리티 의존성 추가

- spring boot 의존성 추가하여 컨트롤러를 통해 경로를 설정한 url로 접근시, 내장 톰캣에 의해 해당 컨트롤러의 동작 or 반환값이 맵핑된다.
- 다만, 단순히 여기까지만 하면 해당 애플리케이션은 보안이 적용되지 않았다는 문제점이 존재한다.
- 그렇다면 애플리케이션에 보안을 적용하기 위한 방법은?
    - spring security 의존성 추가.
    - spring security 의존성을 추가하기만 해도 애플리케이션에 보안이 적용된다.

---

**스프링 시큐리티의 의존성 추가시 일어나는 일들( 따로 설정X, default )**

- 서버가 기동되면 스프링 시큐리티의 초기화 작업 및 보안 설정이 이루어진다.
- 별도의 설정이나 구현을 하지 않아도 기본적인 웹 보안 기능이 현재 시스템에 연동되어 작동한다.
1. 모든 요청은 인증이 되어야 자원에 접근이 가능하다.
2. 인증 방식은 폼 로그인 방식과 httpBasic 로그인 방식을 제공한다.
3. 기본 로그인 페이지를 제공한다.
4. 기본 계정 한개를 제공한다( username : user, password : 랜덤문자열로 서버 기동시 콘솔에 출력됨 ).

---

**스프링 시큐리티가 제공하는 기본( default ) 보안기능 사용시 문제점**

- 계정 추가, 권한 추가, DB 연동 등.
- 기본적인 보안 기능 외에 시스템에서 필요로 하는 더 세부적이고 추가적인 보안기능 필요.

### 02. 인증 API - 사용자 정의 보안 기능 구현

![Untitled](spring%20security%20%E1%84%80%E1%85%B5%E1%84%87%E1%85%A9%E1%86%AB%20api%20%E1%84%86%E1%85%B5%E1%86%BE%20filter%20%E1%84%8B%E1%85%B5%E1%84%92%E1%85%A2(%20FormLog%203976692db0df4df1a24fdc2b8382b03c/Untitled.png)

**스프링 시큐리티의 보안설정들을 커스텀하는 방법**

- 기본적인 보안 기능들을 활성화하고, 세부적인 기능을 위한 API를 제공하는 HttpSecurity 클래스를 생성해주는 WebSecurityAdapter을 상속받은 사용자 정의 클래스 생성( SecurityConfig ).
- 설정 클래스 내부에서 `HttpSecurity` 클래스를 이용하여 세부적인 인증 및 인가 관련 설정들을 커스텀해야 한다.

---

**커스텀 1 : 사용자 계정**

1. 커스텀을 위한 설정 클래스( SecurityConfig ) 생성.
2. HttpSecurity 클래스를 생성하여 인증 및 인가 정책 설정.
    1. 인가 : 별다른 권한 X.
    2. 인증 :
    - formLogin 방식 사용.
    - 계정은 커스텀하여 사용( 더이상 시큐리티가 제공하는 기본값 사용 X ).

```java
@Configuration
@EnableWebSecurity //웹보안 활성화를 위한 애노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http //인증 및 인가 관련 세부 API 제공 클래스
			.authorizeRequests() //인가정책
			.anyRequest().authenticated(); //모든요청에 대해 인증만 필요( 별다른 권한X )
		http
			.formLogin(); //인증정책
	}

}
```

```java
## spring security formLogin에 대한 계정 커스텀
spring.security.user.name=???
spring.security.user.password=???
```

### 03. 인증 API - Form 인증

![Untitled](spring%20security%20%E1%84%80%E1%85%B5%E1%84%87%E1%85%A9%E1%86%AB%20api%20%E1%84%86%E1%85%B5%E1%86%BE%20filter%20%E1%84%8B%E1%85%B5%E1%84%92%E1%85%A2(%20FormLog%203976692db0df4df1a24fdc2b8382b03c/Untitled%201.png)

**Form 인증 방식 단계**

1. 클라이언트가 서버의 자원에 접근 시도.
    - 여기서 자원은 시큐리티 설정에 의해 인증이 필요한 자원들을 말한다.
2. 인증이 되어있는지 확인 후, 인증이 되어있지 않다면 로그인 페이지로 리다이렉트.
3. 로그인 페이지에서 사용자로부터 인증데이터( username, password )를 받는다( POST ).
4. 인증데이터가 올바른 경우,
    - 서버에 session 이 생성된다.
    - 인증 결과를 담은 Authentication 타입의 인증 토큰이 생성된다.
    - 인증 토큰을 담은 SecurityContext를 생성하여 서버의 session에 저장한다.
5. 인증 후, 클라이언트 접근시 서버는 session에 담긴 Authentication 인증 토큰을 확인후, 인증이 된 사용자에 한해 자원에의 접근을 허용.

```java
@Configuration
@EnableWebSecurity //웹보안 활성화를 위한 애노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http //인증 및 인가 관련 세부 API 제공 클래스
			.authorizeRequests() //인가정책
			.anyRequest().authenticated(); //모든요청에 대해 인증만 필요( 별다른 권한X )
		http
			.formLogin() //formLogin 인증 기능이 작동함
			.loginPage("/loginPage") //사용자 정의 로그인 페이지
			.usernameParameter("userId") //아이디 파라미터명 설정( 이때, 아이디 및 패스워드 파라미터명은 로그인시 POST 요청의 form data를 맵핑하기 위한 것으로, 사용자가 정의한 로그인 페이지의 input 태그들의 name과 일치시켜줘야 함 )
			.passwordParameter("passwd") //패스워드 파라미터명 설정
			.loginProcessingUrl("/login_proc") //로그인 form action url( 파라미터와 마찬가지로, 사용자 정의 로그인 페이지 생성시 POST 요청을 맵핑할 url이기 때문에 form의 action과 일치시켜줘야 함 )
			.defaultSuccessUrl("/") //로그인 성공 후 이동 페이지( successHandler 과 둘 중 택 1 )
			.successHandler(new AuthenticationSuccessHandler() { //로그인 성공 후 핸들러
				@Override
				public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
					System.out.println("authentication" + authentication.getName());
					response.sendRedirect("/");
				}
			})
			.failureUrl("/login") //로그인 실페 후 이동 페이지( failureHandler 과 둘 중 택 1 )
			.failureHandler(new AuthenticationFailureHandler() { //로그인 실패 후 핸들러
				@Override
				public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
					System.out.println("exception" + exception.getMessage());
					response.sendRedirect("/login");
				}
			})
			.permitAll(); //인증을 받기 위한 경로는 인증이 되지 않아도 접근할 수 있도록 설정
	}

}
```

```java
@RestController
public class SecurityController {

	@GetMapping("/")
	public String index() {
		return "home";
	}

	@GetMapping("/loginPage")
	public String loginPage() {
		return "loginPage"; //로그인을 하기 위한 실제 View를 반환하도록 해야함
	}

}
```

### 04. 인증 API - UsernamePasswordAuthenticationFilter

![Untitled](spring%20security%20%E1%84%80%E1%85%B5%E1%84%87%E1%85%A9%E1%86%AB%20api%20%E1%84%86%E1%85%B5%E1%86%BE%20filter%20%E1%84%8B%E1%85%B5%E1%84%92%E1%85%A2(%20FormLog%203976692db0df4df1a24fdc2b8382b03c/Untitled%202.png)

**시큐리티 Filter 인증(** UsernamePasswordAuthenticationFilter **) 단계**

- `UsernamePasswordAuthenticationFilter`는 시큐리티 설정에 따른 인증처리를 담당하고 관련 필터들을 구성하는 역할.
1. 현재 요청정보의 url이 /login 인지 여부를 판별.
    - 이때, /login( 매칭할 url )은 loginProcessingUrl()을 통해 설정해준 값( default가 /login ).
    - yes : 나머지 인증절차로 넘긴다.
    - no : 인증처리를 하지 않고 그다음 필터로 넘어간다.
2. 로그인 정보가 일치하다면, 인증객체( Authentication )를 생성하여 인증정보를 담아서 실제 인증절차로 넘긴다( 아직 인증 X ).
3. `AuthenticationManager`이 인증객체를 전달받아 내부 `AuthenticationProvider` 중 하나를 선택해 인증을 위임.
    - AuthenticationProvider가 실제 인증여부를 확인하는 객체.
    - 인증실패시 AuthenticationException을 발생시켜 다시 필터의 처음으로 되돌아간다.
    - 인증성공시 Authentication 객체를 생성하여( 사용자정보, 권한정보 포함 ) AuthenticationManager에 반환.
4. 최종적으로 인증에 성공하여 인증 정보를 담고 있는 Authentication 객체를 인증객체 저장소인 `SecurityContext`에 담아 전역적으로 사용할 수 있도록 session에 담는다.
5. 인증 최종 성공시 successHandler로 넘어가 성공 이후, 작업을 처리.

---

**인증과정 내부코드 이해**

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
	HttpServletRequest request = (HttpServletRequest) req;
	HttpServletResponse response = (HttpServletResponse) res;

	// (1) requiredAuthentication()
	// false : 일치하지 않으면 chain.doFilter를 통해 다음 필터로 넘겨버림
	// true  : 일치하면 인증과정 나머지 계속 진행
	if (!requiredAuthentication(request, response)) {
		chain.doFilter(request, response);
		return;
	}

	...

	Authentication authResult;

	try {
		// (2) attempAuthentication()
		// null     : 인증을 시도한 결과, 실패하여 인증객체가 비어있음
		// not null : 인증을 시도한 결과, 성공하여 최종적으로 사용자 정보, 권한 정보 등의 인증정보가 담긴 객체가 반환됨
		authResult = attempAuthentication(request, response);
		if (authResult == null) {
			return;
		}
		sessionStrategy.onAuthentication(authResult, request, response);
	}

	...
	
	// (4) successfulAuthentication()
	// 최종적으로 성공하여 반환된 인증객체를 저장소(SecurityContext)에 담아 전역적으로 사용될 수 있도록 session에 담는다
	successfulAuthentication(request, response, chain, authResult);	
}

// mathces() 역할?
// 요청정보의 url이 인증요청을 위한(loginProcessingUrl()을 통해 설정된 url)과 일치하는지 여부 판별
protected boolean requiredAuthentication(HttpSErvletRequest request, HttpSErvletResponse response) {
	return requiredAutehnticationRequestMatcher.matches(request);
}

// successfulAuthentication() 역할?
// 인증객체를 SecurityContext에 저장하여 전역적으로 접근할 수 있도록 한다
// 성공 이후의 동작을 실행하기 위해 성공핸들러를 호출한다
protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain, Authenticaion authResult) throws IOException, ServletException {
	
	...
	
	// 성공하여 반환된 인증객체를 SecurityContext에 저장
	// SecurityContextHolder.getContext().getAuthentication()에 의해 전역적으로 접근 가능
	SecurityContextHolder.getContext().setAuthentication(authResult);

	...
	
	// (5) onAuthenticationSuccess()
	// 최종적으로 성공 핸들러 호출하여 성공 이후 동작 실행
	successHandler.onAuthenticationSuccess(request, response, authResult);
}
```

```java
// attempAuthentication() 역할?
// 실제 인증절차를 수행하고, 성공이면 Authentication 객체 반환, 실패하면 예외 혹은 null 반환
public Authentication attempAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
	if (postOnly && !request.getMethod().equals("POST") {
		throw new AuthenticationServiceException("Authentication method is not imported: " + request.getMethod());
	}

	// 사용자로부터 입력받은 인증정보( username, password ) 추출
	String username = obtainUsername(request);
	String password = obtainPassword(request);

	if (username == null) {
		username = "";
	}

	if (password == null) {
		password = "";
	}

	username = username.trim();

	// 추출한 인증정보를 바탕으로 인증객체 생성
	UsernamePasswordAuthenticaionToken authRequest = new UsernamePasswordAuthenticaionToken(
		username, password
	);

	setDetails(request, authRequest);

	// (3) authenticate()
	// 실제 인증절차는 AuthenticationManager에 넘긴다
	// 이때, 위에서 생성한 인증객체를 함께넘긴다
	// Authentication    : 성공시 인증정보가 담긴 인증객체 반환
	// null or Exception : 실패시 예외 혹은 null 반환
	return this.getAuthenticationManager().authenticate(authRequest);
}
```

```java
// authenticate() 역할?
// AuthenticationManager은 시큐리티 설정을 참고하여 그에 맞는 인증 방식을 제공하는 Provider에게 실제 인증을 위임
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
	...
	Authentication result = null;

	// 설정정보에 적합한 AuthenticaionProvider를 찾을 때까지 반복
	for (AuthenticationProvider provider : getProviders()) {
		if (!provider.supports(toTest)) {
			continue;
		}

		...
		
		// 알맞은 Provider을 찾았다면 인증절차 위임( authenticate() 호출 )
		try {
			result = provider.authenticate(authentication);

			if (result != null) {
				copyDetails(authentication, result);
				break;
			}
		}
		
		...
	}
}
```

```java
...

// AuthenticationProvider의 인증성공시 역할?
// 인증객체를 생성하고, 내부에 사용자 정보 및 권한정보를 담는다
UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
	principal, authentication.getCredentials(),
	authoritiesMapper.mapAuthorities(user.getAuthorities()));
result.setDetails(authentication.getDetails());

...
```

### 05. 인증 API - Logout, LogoutFilter

![Untitled](spring%20security%20%E1%84%80%E1%85%B5%E1%84%87%E1%85%A9%E1%86%AB%20api%20%E1%84%86%E1%85%B5%E1%86%BE%20filter%20%E1%84%8B%E1%85%B5%E1%84%92%E1%85%A2(%20FormLog%203976692db0df4df1a24fdc2b8382b03c/Untitled%203.png)

**Logout 단계**

1. 클라이언트의 로그아웃 요청.
    - 이때, 시큐리티가 제공하는 logout 요청은 원칙적으로 POST 방식어야 한다.
2. 로그아웃 요청시 기본적으로 SecurityLogoutSuccessHandler가 작동( 커스텀 가능 ).
    - 세션 무효화.
    - 인증객체 삭제.
    - 쿠키가 존재한다면 쿠키도 삭제.
    - /login 으로 리다이렉트.

```java
@Configuration
@EnableWebSecurity //웹보안 활성화를 위한 애노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		...

		http
			.logout() //로그아웃 기능이 작동함
			.logoutUrl("/logout") //로그아웃 처리 url( default가 logout )
			.logoutSuccessUrl("/login") //로그아웃 성공 후 이동페이지( logoutSuccessHandler 와 둘 중 택 1 )
			.logoutSuccessHandler(new LogoutSuccessHandler() { // 로그아웃 성공 후 핸들러
				@Override
				public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
					response.sendRedirect("/login");
				}
			})
			.deleteCookies("JSESSIONID", "rememeber-me") //로그아웃 후 쿠키 삭제
			.addLogoutHandler(new LogoutHandler() { //로그아웃 핸들러
				@Override
				public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
					HttpSession session = request.getSession();
					session.invalidate();
				}
			});
	}

}
```

---

**LogoutFilter**

![Untitled](spring%20security%20%E1%84%80%E1%85%B5%E1%84%87%E1%85%A9%E1%86%AB%20api%20%E1%84%86%E1%85%B5%E1%86%BE%20filter%20%E1%84%8B%E1%85%B5%E1%84%92%E1%85%A2(%20FormLog%203976692db0df4df1a24fdc2b8382b03c/Untitled%204.png)
