## 프로젝트 구조

각각의 Controller Class는 화면상의 각각의 메뉴에 해당한다:

* [마이페이지 기능](./src/main/java/io/security/corespringsecurity/controller/user/UserController.java)
* [메시지 기능](./src/main/java/io/security/corespringsecurity/controller/user/MessageController.java)
* [환경설정 기능](./src/main/java/io/security/corespringsecurity/controller/admin/ConfigController.java)

---

## 해당 실습코드 목표

### 실전 프로젝트 생성

1. Spring Security Configuration Class를 생성하여 부분적인 인증/인가 관련 설정을 한다.
    - HttpSecurity Api를 통한 antMatchers를 통한 인가설정.
    - HttpSecurity Api를 통한 formLogin을 통한 기본 인증방식 설정.
2. 각각의 메뉴에 해당하는 인가 설정 및 이에 필요한 사용자 권한을 생성한다.
    - UserDetailsService 생성 및 빈등록.
* [Spring Security 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)

---

### 정적 자원 관리 - WebIgnore 설정

1. js/css/image(resources/static/**) 파일 등 보안 필터를 적용할 필요가 없는 리소스를 설정한다.
   - WebSecurity Api를 통한 ignoring() 설정.
* [Spring Security 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)

---

### 사용자 DB 등록 및 PasswordEncoder

> PasswordEncoder
> 비밀번호를 안전하게 암호화하도록 제공.<br>
> ```java 
> PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder(); 
> ```
> 여러개의 PasswordEncoder 유형을 선언한 뒤, 상황에 맞게 선택해서 사용할 수 있도록 지원하는 Encoder이다.<br><br>
> 암호화 포맷 : {id}encodedPassword
>  - 기본 포맷은 Bcrypt : {bcrypt}encodedPassword.
>  - 알고리즘 종류 : bcrypt, noop, pbkdf2, scrypt, sha256.<br>
> ```java
> encode(password) // 패스워드 암호화
> matches(raw, encoded) // 패스워드 비교
> ```

1. 사용자가 입력한 비밀번호를 평문이 아니라, 암호화하여 데이터베이스에 저장함으로써 보안을 강화한다.
   - PasswordEncoder 애플리케이션에서 사용할 수 있도록 스프링 빈으로 등록.
   - PasswordEncoder를 의존성 주입받아 encode() 메서드를 통해 비밀번호 암호화.
* [Spring Security 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)
* [PasswordEncoder encode()](./src/main/java/io/security/corespringsecurity/controller/user/UserController.java)

---

### DB 연동 인증 처리 : CustomUserDetailsService, CustomAuthenticationProvider

1. DB에 저장된 사용자를 인증과정에서 직접 조회하고 인증이 필요한 사용자의 정보와 비교하여 인증을 처리한다.
   - UserDetailsService를 커스텀한 서비스 클래스를 생성하여 DB로부터 사용자를 조회하는 기능 구현.
   - UserDetails를 커스텀한 클래스를 생성하여 DB로부터 사용자를 조회했을때 데이터타입을 생성.
   - SecurityConfiguration 설정파일을 통해 AuthenticationManager을 빈으로 등록하며<br>-> 스프링의 내부 동작으로 인해 작성된 CustomDetailsService와 PasswordEncoder가 자동으로 설정됨.
* [CustomUserDetailsService 사용자 DB 조회 서비스](./src/main/java/io/security/corespringsecurity/security/service/CustomUserDetailsService.java)
* [CustomUserDetails 타입의 사용자 저장용 타입 클래스](./src/main/java/io/security/corespringsecurity/security/service/AccountContext.java)
* [Spring Security 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)

2. DB 조회를 통해 인증되어 최종적으로 반환된 UserDetails 타입의 사용자 객체를 통해 추가적인 인증을 처리한다.
   - AuthenticationProvider을 커스텀한 Provider 클래스를 생성하여 DB로부터 조회된 사용자(UserDetails)와 입력된 인증정보(authentication)를 통해 실제 인증 수행.
   - 최종 생성된 UsernamePasswordAuthenticationToken(인증토큰)을 애플리케이션에서 사용할 수 있도록 설정파일에 설정.
* [CustomAuthenticationProvider 사용자 최종 인증 provider](./src/main/java/io/security/corespringsecurity/security/provider/CustomAuthenticationProvider.java)
* [Spring Security 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)

---

### 로그아웃 및 인증에 따른 화면 보안 처리

> 로그아웃 방법
> - \<form> 태그를 사용해서 POST로 요청.
> - \<a> 태그를 사용해서 GET으로 요청 - SecurityContextLogoutHandler 활용.
> 
> ```java
> @GetMapping("/logout")
> public String logout(HttpServletRequest request, HttpServletResponse response) {
>   Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
>   if (authentication != null) {
>       new SecurityContextLogoutHandler().logout(request, response, authentication);
>   }
>   return "redirect:/login";
> }
> ```

1. SecurityContextLogoutHandler 객체를 통해 스프링 시큐리티가 제공하는 방식의 로그아웃을 수행하도록 한다.
   - GET 요청을 통해 전역 인증 객체(Authentication)를 활용하여 로그아웃을 한다
* [GET 요청 방식으로 로그아웃 핸들러 생성](./src/main/java/io/security/corespringsecurity/controller/login/LoginController.java)

---

### 인증 부가 기능 - WebAuthenticationDetails, AuthenticationDetailSource

<img width="644" alt="스크린샷 2023-12-14 오후 2 25 09" src="https://github.com/hgene0929/hgene0929/assets/90823532/4929cf11-d2dc-4018-bc40-a260975c2c8c">

> WebAuthenticationDetails
> - 인증 과정 중 전달된 데이터를 저장.
> - Authentication의 detils 속성에 저장.
> 
> AuthenticationDetailsSource
> - WebAuthenticationDetails 객체를 생성.

1. 인증 객체(Authentication) 생성 이후에, id와 pw 이외에 입력된 부가적인 데이터들을 저장하여 활용가능하도록 한다.
   - 사용자가 로그인시 입력하는 id,pw 이외의 부가정보를 Request 객체로부터 추출하여 저장.
   - 위의 부가정보를 추출 및 저장하는 역할을 하는 WebAuthenticationDetails 객체를 생성하기 위한 Source 클래스 생성.
   - 로그인시 해당 부가정보 저장 객체가 작동할 수 있도록 설정.
   - 최종적으로 Authentication 객체에 저장된 부가정보를 인증과정에서 활용.
* [WebAuthenticationDetails를 커스텀하여 부가정보를 저장하는 클래스](./src/main/java/io/security/corespringsecurity/security/common/FormWebAuthenticationDetails.java)
* [WebAuthenticationDetails의 객체를 생성하고, Request를 전달하는 클래스](./src/main/java/io/security/corespringsecurity/security/common/FormAuthenticationDetailsSource.java)
* [Spring Security 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)
* [CustomAuthenticationProvider 사용자 최종 인증 provider](./src/main/java/io/security/corespringsecurity/security/provider/CustomAuthenticationProvider.java)

--- 

### 인증 성공/실패/인가거부 핸들러 - CustomAuthenticationSuccessHandler, CustomAuthenticationFailureHandler, AccessDeniedHandler

1. 스프링 시큐리티가 제공하는 AuthenticationSuccessHandler를 상속받아 인증성공시 처리되어야 하는 로직을 등록한다.
   - 인증 캐시를 활용하여 이전에 사용자가 인증성공 이전에 가고자 했던 url로 인증이 성공했을 경우 바로 갈 수 있도록 하는 로직 구현.
   - 앞서 구현한 SuccessHandler를 설정파일에 등록하여 사용할 수 있도록 함.
* [AuthenticationSuccessHandler 구현](./src/main/java/io/security/corespringsecurity/security/handler/CustomAuthenticationSuccessHandler.java)
* [Spring Security 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)

2. 스프링 시큐리티가 제공하는 AuthenticationFailureHandler를 상속받아 인증실패시 후속작업을 등록한다.
   - 인증 과정에서 실패에 의해 발생하는 예외(UsernameNotFoundException, BadCredentialException, ...)들에 대한 처리 로직 구현.
   - 인증 실패시 요청될 url의 쿼리스트링으로 예외메시지 전달하여 화면에 띄울 수 있도록 함.
   - 앞서 구현한 FailureHandler를 설정파일에 등록하여 사용할 수 있도록 함.
* [AuthenticationFailureHandler 구현](./src/main/java/io/security/corespringsecurity/security/handler/CustomAuthenticationFailureHandler.java)
* [Controller에 쿼리스트링을 전달하여 예외메시지를 화면에 전달](./src/main/java/io/security/corespringsecurity/controller/login/LoginController.java)
* [Spring Security 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)

3. 인증은 성공했으나, 특정 자원에 대한 접근 권한이 없을 경우(인가예외)에 대한 후속작업을 등록한다.
   - 인가 과정에서 실패에 의해 발생하는 예외 객체를 받아와 메시지를 쿼리스트링 형태로 전달.
   - 인가 예외 페이지로 이동하는 컨트롤러는 해당 사용자가 자원에 접근할 수 없다는 메시지를 띄우기 위해 예외 메시지 뿐만 아니라, 사용자 정보도 함께 화면에 보냄.
   - 앞서 구현한 accessDeniedHandler를 설정파일에 등록하여 사용할 수 있도록 함.
* [AccessDeniedHandler 구인](./src/main/java/io/security/corespringsecurity/security/handler/CustomAccessDeniedHandler.java)
* [Controller에 쿼리스트링을 전달하여 예외메시지를 화면에 전달](./src/main/java/io/security/corespringsecurity/controller/login/LoginController.java)
* [Spring Security 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)
