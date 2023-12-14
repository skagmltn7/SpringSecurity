# spring security 기본 api 및 filter 이해( 권한 )

---

### 12. 인가 API - 권한 설정 및 표현식

- 스프링 시큐리티가 제공하는 권한 설정 방식 :
1. 선언적 방식 :
    1. URL
    2. Method

```java
@Configuration
@EnableWebSecurity //웹보안 활성화를 위한 애노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	//사용자를 생성하고 권한을 부여하는 방식 중 하나( 메모리 방식 )
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER"); //{noop}은 패스워드 암호화시 prefix 형태로 암호화유형을 지정해주는 것
		auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER"); //일반적으로 admin 권한을 가진 사용자는 가장 많은 권한을 가진다( 일반 사용자의 권한도 공유 ) 따라서, 모두 다 선언한 것 => role_hierachy를 통해 해결 가능
		auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
	}

	@Autowired
	UserDetailsService userDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//주의사항 : 설정시 구체적인 경로가 먼저 오고 그것 보다 큰 범위의 경로가 뒤에 오도록 해야 한다
		http //선언적 방식( URL )
			.antMatcher("/shop/**") //아래 설정된 인가정책은 현재의 URL로 접근할 때만 유효함( 특정한 자원을 제한 ), 생략시 모든 요청에 대한 인가 정책
			.authorizeRequests() //인가정책
			.antMatchers("/shop/login", "/shop/users/**").permitAll() //모두 허용
			.antMatchers("/shop/mypage").hasRole("USER") //USER 권한을 가진 사용자만 허용
			.antMatchers("/shop/admin/pay").access("hasRole('ADMIN')") //ADMIN 권한을 가진 사용자만 허용
			.antMatchers("/shop/admin/**").access("hasRole('ADMIN') or hasRole('SYS')") //ADMIN 이나 SYS 권한을 가진 사용자만 허용
			.anyRequest().authenticated(); //모든요청에 대해 인증만 필요( 별다른 권한X )
	}

}
```

1. 동적 방식( DB 연동 프로그래밍 ) :
    1. URL
    2. Method

- 인가 API 표현식 :

| 메서드 | 동작 |
| --- | --- |
| authenticated() | 인증된 사용자의 접근을 허용. |
| fullyAuthenticated() | 인증된 사용자의 접근을 허용, rememberMe 인증 제외. |
| permitAll() | 무조건 접근을 허용. |
| denyAll() | 무조건 접근을 허용하지 않음. |
| anonymous() | 익명사용자의 접근을 하용( 일반 사용자는 허용 X ). |
| rememberMe() | 기억하기를 통해 인증된 사용자의 접근을 허용. |
| access(String) | 주어진 SpEL 표현식의 평가 결과가 true이면 접근 허용. |
| hasRole(String) | 사용자가 주어진 역할이 있다면 접근 허용. |
| hasAuthority(String) | 사용자가 주어진 권한이 있다면 접근을 허용. |
| hasAnyRole(String…) | 사용자가 주어진 권한이 있다면 접근을 허용. |
| hasAnyAutority(String…) | 사용자가 주어진 권한 중 어떤 것이라도 있다면 접근을 허용. |
| hasIpAddress(String) | 주어진 IP로부터 요청이 왔다면 접근을 허용. |
