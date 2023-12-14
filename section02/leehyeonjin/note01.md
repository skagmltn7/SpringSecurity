# 스프링 시큐리티 주요 아키텍처 이해( 필터 )

---

### 1. DelegatingFilterProxy, FilterChainProxy

<img width="643" alt="Untitled" src="https://github.com/hgene0929/hgene0929/assets/90823532/e97e17fb-7faf-42c4-a539-092251e43e1e">

<img width="684" alt="Untitled (1)" src="https://github.com/hgene0929/hgene0929/assets/90823532/a9d08975-ecc0-49a8-9714-3c16378fea61">

1. 서블릿 필터는 스프링에서 정의된 빈을 주입해서 사용할 수 없다.
    - 서블릿 필터는 서블릿 컨테이너가 범위이지만, 스프링빈은 스프링 컨테이너가 범위이기 때문이다.
    - 그러나 스프링 시큐리티는 필터기반으로 보안동작을 하기 때문에, 서블릿 필터에서 스프링 빈을 찾아서 사용할 수 있어야 한다.
2. 특정한 이름을 가진 스프링 빈을 찾아 그 빈에게 요청을 위임해야 한다.
    - `springSecurityFilterChain` 이름으로 생성된 빈을 ApplicationContext에서 찾아 요청을 위임한다.
    - 실제 보안처리를 하지 않는다.

---

**DelegatingFilterProxy**

- 요청을 가장 먼저 받아와서 대리자로서, 요청을 받아와 보안 필터를 하도록 만들어진 스프링 빈이 해당 요청을 처리할 수 있도록 위임한다.
- 해당 클래스를 통해 스프링 빈(서블릿 컨테이너가 아님에도 불구하고)이 필터 기반으로 동작할 수 있다.

---

**FilterChainProxy**

- springSecurityFilterChain의 이름으로 생성되는 필터 빈.
- DelegatingFilterProxy으로부터 요청을 위임 받고 실제 보안 처리.
- 스프링 시큐리티 초기화시 생성되는 필터들을 관리하고 제어한다.
    - 스프링 시큐리티가 기본적으로 생성하는 필터.
    - 설정 클래스에서 API 추가시 생성되는 필터.
- 사용자의 요청을 필터 순서대로 호출하여 전달한다.
- 사용자 정의 필터를 생성해서 기존의 필터 전,후로 추가 가능.
    - 필터의 순서를 잘 정의.
- 마지막 필터까지 인증 및 인가 예외가 발생하지 않으면 보안 통과.

### 2. 필터 초기화와 다중 보안 설정

<img width="460" alt="Untitled (2)" src="https://github.com/hgene0929/hgene0929/assets/90823532/fb65acad-0b02-459c-9fa3-454a21634154">

**다중 설정 클래스**

- 설정 클래스별로 보안 기능이 각각 작동한다.
- 설정 클래스별로 RequestMatcher 설정.
- 설정 클래스 별로 필터가 생성된다.
- FilterChainProxy가 각 필터들을 가지고 있다.
- 요청에 따라 RequestMatcher와 매칭되는 필터가 작동하도록 한다.
    - 두 개 인증 필터(설정클래스)를 모두 가진 FilterChainProxy는 요청이 들어오면 둘 중 누구의 설정을 따라야 할 지 판단하기 위해 matches 를 통해 두 개의 RequestMatcher 이하의 url을 우선 판단.
- 다중 설정 클래스 :

```java
@Configuration
@EnableWebSecurity
@Order(0) //설정클래스가 초기화되는 순서 지정( 없으면 오류 발생 )
public class SecurityConfig1 extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.antMatcher("/admin/**") //특정 URL에 대해서만 해당 보안 설정 클래스가 작동하도록 설정
			.authorizeRequests()
			.anyRequests().authenticated()
		.and()
			.httpBasic();
	}

}

@Configuration
@Order(1)
public class SecurityConfig2 extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http //어떤 요청에도 해당 설정 클래스의 보안 설정이 작동하도록 설정
			.authorizeRequests() 
			.anyRequests().permitAll()
		.and()
			.formLogin();
	}

}
```
