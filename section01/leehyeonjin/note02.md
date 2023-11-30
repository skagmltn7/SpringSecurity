# spring security 기본 api 및 filter 이해( 추가 인증 설정 )

---

### 07. 인증 API - Remember Me 인증

- 세션이 만료되고 웹 브라우저가 종료된 후에도 애플리케이션이 사용자를 기억하는 기능.
- Remember-Me 쿠키에 대한 http 요청을 확인한 후 토큰 기반 인증을 사용해 유효성을 검사하고, 토큰이 검증되면 사용자는 로그인 된다.
- 사용자 라이프 사이클 :
    - 인증 성공( Remember-Me 쿠키 설정 ).
    - 인증 실패( 쿠키가 존재하면 쿠키 무효화 ).
    - 로그아웃( 쿠키가 존재하면 쿠키 무효화 ).

```java
@Configuration
@EnableWebSecurity //웹보안 활성화를 위한 애노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	UserDetailsService userDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.rememberMe() //remember me 기능이 작동함
			.rememberMeParameter("remember") //true일때 remember me 옵션을 켜줄 파라미터명 지정( default가 remember )
			.tokenValiditySeconds(3600) //쿠키가 저장될 기간( default가 14일 )
			.alwaysRemember(false) //remember me 기능이 활성화되지 않아도 항상 실행
			.userDetailsService(userDetailsService); //remember me 인증시, 사용자 정보를 조회하는 과정에서 필요한 서비스 클래스
	}

}
```

### 08. 인증 API - RememberMeAuthenticationFilter

![Untitled](spring%20security%20%E1%84%80%E1%85%B5%E1%84%87%E1%85%A9%E1%86%AB%20api%20%E1%84%86%E1%85%B5%E1%86%BE%20filter%20%E1%84%8B%E1%85%B5%E1%84%92%E1%85%A2(%20%E1%84%8E%E1%85%AE%E1%84%80%E1%85%A1%20%E1%84%8B%E1%85%B5%2058fe7815324c40908c34981123dc9ddd/Untitled.png)

`RememberMeAuthenticationFilter`**가 요청을 받아 처리하기 위한 조건**

- 인증객체( Authentication )가 null이어야 한다.
    - 인증객체가 null인 경우 : 해당 사용자의 session이 만료되었거나, 세션연결이 끊겨 더이상 세션안에서 SecurityContext를 찾지 못하고, 따라서 SecurityContext 안의 Authentication에도 접근할 수 없는 경우.
- Form 인증시, 사용자가 remember-me 쿠키를 request header에 함께 보내야 한다.
- RememberMeServices
    - remember me 기능을 구현하기 위한 로직을 담은 인터페이스.
    1. TokenBasedRememberMeServices : 메모리에서 제작한 토큰과 사용자 요청 헤더의 토큰을 비교.
    2. PersistentTokenBasedRememberMeServices : 영구적인 방식, DB에 발급한 토큰을 저장하고 해당 토큰과 사용자 요청 헤더의 토큰을 비교.

---

`RememberMeServices` **단계**

1. 사용자 요청 헤더로부터 토큰 쿠키 추출.
2. 사용자가 가진 쿠키가 remember-me 라는 이름의 토큰인지 검사.
3. 토큰을 디코드( 정상 규칙을 준수하는지 확인 ).
4. 토큰에 포함된 값과 현재 서버의 값의 일치여부 확인.
5. 해당 토큰에 포함된 사용자정보와 DB에 저장된 사용자 정보가 존재하는지 확인.
6. 새로운 인증객체(RememberMeAuthenticationToken ) 생성.

### 09. 인증 API - AnonymousAuthenticationFilter

![Untitled](spring%20security%20%E1%84%80%E1%85%B5%E1%84%87%E1%85%A9%E1%86%AB%20api%20%E1%84%86%E1%85%B5%E1%86%BE%20filter%20%E1%84%8B%E1%85%B5%E1%84%92%E1%85%A2(%20%E1%84%8E%E1%85%AE%E1%84%80%E1%85%A1%20%E1%84%8B%E1%85%B5%2058fe7815324c40908c34981123dc9ddd/Untitled%201.png)

`AnonymousAuthenticationFilter`**의 존재이유**

- 인증되지 않은 사용자의 인증객체( Authentication )를 null로 처리하지 않고, 별도의 익명사용자용 객체로 만들어 사용.
- 인증 사용자와 익명 사용자를 구분하기 위한 용도 : 화면에서 인증 여부를 구현할 때 isAnonymouse()와 isAuthenticated()로 구분해서 사용.
- 인증객체를 세션에 저장하지 X.

> **Q. 왜 굳이 로그인을 하지 않은 상태의 사용자 인증객체를 따로 생성하는가?**
>
> - 스프링 시큐리티에서 인증받지 않은 상태를 판별하는 기준은 user 객체의 존재여부가 아님. 
>   - 즉, user가 null이라도 Authentication이 null이 아니라면 인증받은 것으로 간주하기도 함. 
>   - Ex. 세션이 만료되거나 무효화되어서 인증이 필요한 상태는 맞지만, 익명사용자는 아닌 경우.
> - 따라서 스프링 시큐리티에서는 익명사용자라 할지라도 Authentication 객체를 별도로 할당함으로써 인증 사용자와 익명사용자를 구분하여 적절한 분기를 탄다.
