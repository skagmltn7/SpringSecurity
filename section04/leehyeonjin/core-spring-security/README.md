## 해당 실습코드 목표

### Ajax 인증 - 흐름 및 개요

<img width="842" alt="스크린샷 2023-12-14 오후 7 48 44" src="https://github.com/hgene0929/hgene0929/assets/90823532/36747fad-5d89-49de-a0ba-fe595bf3535d">

> Form 인증 vs Ajax 인증
> - Form 인증 : 동기적인 방식.
> - Ajax 인증 : 비동기적인 방식.

---

### Ajax 인증 - AjaxAuthenticationFilter

> 1. AbstactAuthenticationProcessingFilter 상속.
> 2. 필터 작동 조건 : AntPathRequestMatcher("/api/login")로 요청정보와 매칭하고 요청 방식이 Ajax이면 필터 작동.
> 3. AjaxAuthenticationToken을 생성하여 AuthenticationManager에게 전달하여 인증처리.
> 4. Filter 추가
> ```java
> http.addFilterBefore(AjaxAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
> ```

1. Ajax 전용 인증 필터를 구성하여 사용자가 ajax(비동기) 방식으로 인증요청을 보낼 경우, 해당 필터를 통해 인증처리를 할 수 있도록 한다.
    - AbstractAuthenticationProcessingFilter(대부분의 인증필터 기능을 가지는 추상 클래스)를 상속받아 커스텀하여 필요한 기능(ajax 방식)의 인증 필터 생성.
    - 해당 필터가 작동할 조건(url, 요청방식)을 등록.
    - AjaxAuthenticationToken이라는 해당 필터용 인증 객체를 생성하여 이후 실제 인증시 AuthenticationManager가 이용할 수 있도록 함.
    - 스프링 시큐리티 설정파일을 통해 해당 필터를 스프링 시큐리티 인증 필터체인에 등록하여 사용할 수 있도록 함.
* [Ajax용 인증 필터 커스텀](./src/main/java/io/security/corespringsecurity/security/filter/AjaxLoginProcessingFilter.java)
* [Ajax용 인증 객체 커스텀](./src/main/java/io/security/corespringsecurity/security/token/AjaxAuthenticationToken.java)
* [Ajax용 인증 처리 Provider 커스텀](./src/main/java/io/security/corespringsecurity/security/provider/AjaxAuthenticationProvider.java)
* [intellij가 제공하는 API 테스트 툴을 통한 Ajax API 테스트](./src/main/ajax.http)

---

### 인증 처리자 - AjaxAuthenticationProvider

1. Ajax 전용 인증 필터가 실행되어 토큰이 생성되고 manager로부터 받아온 요청을 Ajax 인증 필터에 맞게 실제 인증을 처리할 수 있도록 한다.
   - 별도의 스프링 시큐리티 설정 파일(Ajax용)을 생성하여 Ajax 인증 처리 과정에 필요한 filter, Manager, Provider, Handler를 등록.
   - Ajax용 Provider를 커스텀하여 구성함으로써 Ajax용 인증 객체를 실제 인증처리할 때 사용할 수 있도록 구성.
* [Spring Security 설정 파일에 Ajax용 필터 빈등록 및 설정](./src/main/java/io/security/corespringsecurity/security/configs/AjaxSecurityConfig.java)
* [Ajax용 인증 처리 Provider 커스텀](./src/main/java/io/security/corespringsecurity/security/provider/AjaxAuthenticationProvider.java)

---

### 인증 핸들러 - AjaxAuthenticationSuccessHandler, AjaxAuthenticationFailureHandler

1. 인증 성공시, Ajax 방식(비동기)에 따라 화면이 아닌 인증성공의 최종적인 결과값들을 response body에 담아서 반환하도록 한다.
   - 인증성공의 결과 객체를 파라미터로 받아와 인증성공시 response body 담아 클라이언트로 응답하는 커스텀 핸들러 생성.
* [Ajax용 SuccessHandler 커스텀](./src/main/java/io/security/corespringsecurity/security/handler/AjaxAuthenticationSuccessHandler.java)

2. 인증 실패시, Ajax 방식(비동기)에 따라 화면이 아닌 인증실채의 최종적인 결과값들을 response body에 담아서 반환하도록 한다.
   - 인증실패의 예외 객체를 파라미터로 받아와 인증실패시 response body 담아 클라이언트로 응답하는 커스텀 핸들러 생성.
* [Ajax용 FailureHandler 커스텀](./src/main/java/io/security/corespringsecurity/security/handler/AjaxAuthenticationFailureHandler.java)

3. 만들어둔 Ajax용 Handler들을 스프링 시큐리티 설정파일을 통해 등록해서 인증 성공/실패시 작동할 수 있도록 한다.
   - 별도의 스프링 시큐리티 설정 파일(Ajax용)을 생성하여 Ajax 인증 처리 과정에 필요한 Handler를 등록.
* [Spring Security 설정 파일에 Ajax용 필터 빈등록 및 설정](./src/main/java/io/security/corespringsecurity/security/configs/AjaxSecurityConfig.java)

---

### 인증 및 인가 예외 처리 - AjaxLoginUrlAuthenticationEntryPoint, AjaxAccessDeniedHandler

> FilterSecurityInterceptor는 최종 자원 접근에 대한 사용자의 인증/인가 권한을 검증한다.
> - 인증 : 해당 사용자가 익명사용자라면 AuthenticationEntryPoint를 호출하여 예외를 발생시킴.
> - 인가 : 해당 사용자가 권한이 없다면 AccessDeniedHandler를 호출하여 예외를 발생시킴.

1. 인증 성공을 하지 못한 사용자가 인증이 필요한 자원에 접근 요청을 했을때, 해당 사용자가 다시 인증을 받을 수 있도록 한다.
   - AuthenticationEntryPoint를 커스텀하여 자원에 대한 인증 요청.
* [Ajax용 AuthenticationEntryPoint 커스텀](./src/main/java/io/security/corespringsecurity/security/common/AjaxLoginAuthenticationEntryPoint.java)

2. 인증 성공은 했으나 접근하려는 자원에 대한 권한이 없는 사용자에 대한 응답 처리를 한다.
   - AccessDeniedHandler를 커스텀하여 자원에 대한 권한 요청.
* [Ajax용 AccessDeniedHandler 커스텀](./src/main/java/io/security/corespringsecurity/security/handler/AjaxAccessDeniedHandler.java)

3. 만들어둔 Ajax용 Handler들을 스프링 시큐리티 설정파일을 통해 등록해서 인증 성공/실패시 작동할 수 있도록 한다.
   - 별도의 스프링 시큐리티 설정 파일(Ajax용)을 생성하여 Ajax 인증 처리 과정에 필요한 Handler를 등록.
* [Spring Security 설정 파일에 Ajax용 필터 빈등록 및 설정](./src/main/java/io/security/corespringsecurity/security/configs/AjaxSecurityConfig.java)

---

### Ajax Custom DSLs 구현하기

> Custom DSLs(도메인 특화 언어)
> - AbstractHttpConfigurer
>   - 스프링 시큐리티 초기화 설정 클래스.
>   - 필터, 핸들러, 메서드, 속성 등을 한 곳에 정의하여 처리할 수 있는 편리함 제공.
>   - public void init(H http) throws Exception : 초기화.
>   - public void configure(H http) : 설정.
> - HttpSecurity의 apply(C configurer) 메서드 사용.

1. 스프링 시큐리티에서 제공하는 특정 도메인을 사용하기 위한 언어를 사용하여 특정 도메인을 사용한다.
   - init(), configurer() 메서드를 구현하여 스프링 시큐리티 설정을 초기화 및 등록.
   - apply() 메서드를 구현하여 앞서 초기화 해둔 설정들을 적용.
* [Ajax용 AbstractHttpConfigurer 커스텀](./src/main/java/io/security/corespringsecurity/security/configs/AjaxLoginConfigurer.java)
* [Spring Security 설정 파일에 커스텀한 configurer 적용](./src/main/java/io/security/corespringsecurity/security/configs/AjaxSecurityConfig.java)

---

### Ajax 로그인 구현 & CSRF 설정

> 헤더 설정
> - 전송 방식이 Ajax인지 여부를 위한 헤더설정
> ```java
> xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
> ```
> - CSRF 헤더 설정
> ```html
> <meta id="_csrf" name="_csrf" th:content="${_csrf.token}"/>
> <meta id="_csrf_header" name="_csrf_header" th:content="${_csrf.headerName}"/>
> ```
> ```javascript
> var csrfHeader = $('meta[name="_csrf_header"]').attr('content')
> var csrfToken = $('meta[name="_csrf"]').attr('content')
> xhr.setRequestHeader(csrfHeader, csrfToken)
> ```
