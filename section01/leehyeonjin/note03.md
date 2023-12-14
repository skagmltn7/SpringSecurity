# spring security 기본 api 및 filter 이해( 세션 )

---

### 10. 인증 API - 동시 세션 제어 / 세션 고정 보호 / 세션 정책

**동시 세션 제어**

- 동일한 계정으로 인증을 받을 수 있는 세션의 허용개수가 초과되었을 때 제어하는 방법.
- 스프링 시큐리티의 동시 세션 제어 방법

<img width="686" alt="Untitled (9)" src="https://github.com/hgene0929/hgene0929/assets/90823532/82ecbbdb-6086-44c8-88ba-994f3a45b9eb">

1. 이전 사용자 세션 만료 : 동일한 계정이 세션을 초과하면, 이전에 로그인 되어있던 사용자의 세션을 만료시킴.
2. 현재 사용자 인증 실패 : 동일한 계정이 세션을 초과하면, 새로운 로그인을 차단시켜버림.
- 동시 세션 제어 API :

```java
@Configuration
@EnableWebSecurity //웹보안 활성화를 위한 애노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	UserDetailsService userDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.sessionManagement() //세션 관리 기능이 작동함
			.invalidSessionUrl("/invalid") //세션이 허용되지 않은 경우 이동할 페이지
			.maximumSessions(1) //최대 허용 가능 세션 수( -1 : 무제한 로그인 세션 허용 )
			.maxSessionsPreventsLogin(true) //동시 로그인 차단함( false : 기존 세션 만료, default )
			.expiredUrl("/expired"); //세션이 만료된 경우 이동할 페이지( invalidSessionUrl 과 함께 설정된 경우, invalidSessionUrl이 우선권을 가짐
	}

}
```

---

**세션 고정 보호**

<img width="489" alt="Untitled (10)" src="https://github.com/hgene0929/hgene0929/assets/90823532/a7d0bdfc-9e77-4c3e-b597-ce2dd76206ba">

- 공격자의 세션 고정 공격 상황 :
    - 공격자가 서버(WebApp)에 접근하여 쿠키를 심어둠.
    - 공격자가 심어둔 쿠키를 서버에서 사용자에게 전달.
    - 사용자가 공격자가 심어둔 쿠키로 로그인하여 세션이 생성되면, 해당 세션 인증에 사용된 쿠키를 알고 있는 공격자도 그 세션을 통해 인증을 받을 수 있음.
- 세션 고정 보호 :
    - 위와 같은 상황의 공격을 방지하고자 스프링 시큐리티가 제공.
    - 사용자가 인증을 받을 때마다 새로운 세션과 세션ID(쿠키)를 발급하여 공격자가 계속해서 인증을 유지하는 것을 방지.
- 세션 고정 보호 API :

```java
@Configuration
@EnableWebSecurity //웹보안 활성화를 위한 애노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	UserDetailsService userDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.sessionManagement() //세션 관리 기능이 작동함
			.sessionFixation().changeSessionId(); //세션 고정 보호( default : changeSessionId; none, migrationSession, newSession )
	}

}
```

---

**세션 정책**

- 종류 :
    - SessionCreationPolicy.AlWAYS : 스프링 시큐리티가 항상 세션 생성.
    - SessionCreationPolicy.IF_REQUIRED : 스프링 시큐리티가 필요 시 생성(default).
    - SessionCreationPolicy.NEVER : 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용.
    - SessionCreationPolicy.STATELESS : 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음.
- 세션 정책 API :

```java
@Configuration
@EnableWebSecurity //웹보안 활성화를 위한 애노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	UserDetailsService userDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.sessionManagement() //세션 관리 기능이 작동함
			.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) //세션 정책 설정
	}

}
```

### 11. 인증 API - SessionManagementFilter, ConcurrentSessionFilter

**SessionManagementFilter**

1. 세션 관리 : 인증시 사용자의 세션정보를 등록, 조회, 삭제 등의 이력 관리.
2. 동시적 세션 제어 : 동일 계정으로 접속이 허용되는 최대 세션수를 제한.
3. 세션 고정 보호 : 인증할 때마다 세션쿠키를 새로 발급하여 공격자의 쿠키 조작 방지.
4. 세션 생성 정책 : Always, If_Required, Never, Stateless.

---

**ConcurrentSessionFilter**

- 매 요청마다 현재 사용자의 세션 만료 여부 체크.
- 세션이 만료되었을 경우(session.isExpired() == true), 즉시 만료 처리.
    - 로그아웃 처리.
    - 즉시 오류 페이지 응답(This session has been expired).
- SessionManagementFilter & ConcurrentSessionFilter가 연계하여 동시적 세션 처리를 수행하는 방법 :

<img width="680" alt="Untitled (11)" src="https://github.com/hgene0929/hgene0929/assets/90823532/5af97313-ba3c-46be-8236-1b842b401888">

- SessionManagementFilter & ConcurrentSessionFilter의 세션 관련 처리 과정 :

<img width="719" alt="Untitled (12)" src="https://github.com/hgene0929/hgene0929/assets/90823532/842eaaf2-2a40-495d-856f-e00909e2d28d">

1. 로그인시도 → ConcurrentSessionControlAuthenticationStrategy 라는 동시적 세션 제어를 하는 클래스 호출(세션개수에 따라 동작).
2. ChangeSessionIdAuthenticationStrategy 클래스를 호출하여 세션 고정 보호를 위한 정책 수행.
3. RegisterSessionAuthenticationStrategy 클래스를 통해 사용자의 세션정보 기록(여기서 세션개수가 올라감).
- UsernamePasswordAuthenticationFilter(인증필터)가 각각의 세션에 필요한 클래스를 호출하며 설정하는 것.
