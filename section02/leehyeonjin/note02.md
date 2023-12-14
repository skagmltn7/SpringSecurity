# 스프링 시큐리티 주요 아키텍처 이해( 인증 )

---

### 3. 인증 개념 이해 - Authentication

- 사용자의 인증 정보를 저장하는 토큰 개념.
- 인증시 id와 password를 담고 인증 검증을 위해 전달되어 사용된다.
- 인증 후 최종 인증 결과( user 객체, 권한정보 )를 담고 SecurityContext에 저장되어 전역적으로 참조가 가능하다.

```java
Authentication authentication = SecurityContextHolder.getContext().getAuthentication()
```

- 구조 :
    - principal : 사용자 아이디 혹은 User 객체 저장.
    - credentials : 사용자 비밀번호.
    - authorities : 인증된 사용자의 권한 목록.
    - details : 인증 부가 정보.
    - Authenticated : 인증 여부.
- Authentication 인증객체 생성 흐름 :

<img width="643" alt="Untitled (3)" src="https://github.com/hgene0929/hgene0929/assets/90823532/a7df9369-3eab-4603-a0e2-d08864721bb5">

1. 사용자 로그인시, 인증 필터(UsernamePasswordAuthenticationFilter)를 거치면서 인증 요청 정보가 옳다면, 인증이 되지 않은 인증객체 생성.
2. AuthenticationManager를 거치며 인증객체의 인증이 완료되어 SecurityContext에 저장되어 전역적으로 접근가능한 객체가 된다.

### 4. 인증 저장소 - SecurityContextHolder, SecurityContext

**SecurityContext**

- Authentication 객체가 저장되는 보관소로 필요시 언제든지 Authentication 객체를 꺼내어 쓸 수 있도록 제공되는 클래스.
- ThreadLocal에 저장되어 아무곳에서나 참조가 가능하도록 설계함.
- 인증이 완료되면 HttpSession에 저장되어 애플리케이션 전반에 걸쳐 전역적인 참조가 가능하다.

---

**SecurityContextHolder**

- SecurityContext 객체 저장 방식.
    - MODE_THREADLOCAL : 스레드당 SecurityContext 객체를 할당, default.
    - MODE_INHERITABLETHREADLOCAL : 메인 스레드와 자식 스레드에 관하여 동일한 SecurityContext를 유지.
    - MODE_GLOBAL : 응용 프로그램에서 단 하나의 SecurityContext를 저장한다.
- SecurityContextHolder.clearContext() : SecurityContext 기존 정보 초기화.

### 5. 인증 저장소 필터 - SecurityContextPersistenceFilter

<img width="709" alt="Untitled (4)" src="https://github.com/hgene0929/hgene0929/assets/90823532/16bdec2b-854f-4c59-a4c6-78a5261755fa">

- SecurityContext 객체의 생성, 저장, 조회.
- 익명 사용자 :
    - 새로운 SecurityContext 객체를 생성하여 SecurityContextHolder에 저장.
    - AnonymousAuthenticationFilter에서 AnonymouseAuthenticationToken 객체를 SecurityContext에 저장.
- 인증 시 :
    - 새로운 SecurityContext 객체를 생성하여 SecurityContextHolder에 저장.
    - UsernamePasswordAuthenticationFilter에서 인증 성공 후 Securitycontext에 UsernamePasswordAuthentication 객체를 SecurityContext에 저장.
    - 인증이 최종 완료되면 Session에 SecurityContext를 저장.
- 인증 후 :
    - Session에서 SecurityContext를 꺼내어 SecurityContextHolder에 저장.
    - Securitycontext 안에 Authentication 객체가 존재하면 계속 인증을 유지한다.
- 최종 응답 시 공통 :
    - SecurityContextHolder.clearContext()

### 6. 인증 흐름 이해 - Authentication Flow

<img width="718" alt="Untitled (5)" src="https://github.com/hgene0929/hgene0929/assets/90823532/8139ffd3-4405-44c4-96f8-79a62e92cd47">

1. `UsernamPasswordAuthenticationFilter`가 Authentication 인증객체 생성.
    - 로그인 요청시 사용자가 입력한 인증정보(id, password)를 담음.
    - authenticate() 을 호출하여 AuthenticationManager에 인증처리 위임.
    - 이때 Authentication 인증객체 전달.
2. `AuthenticationManager`가 인증을 관리.
    - 실제 인증처리(id, password 검증)를 맡길 AuthenticationProvider를 관리.
    - authenticate() 을 호출하여 실제 인증처리를 AuthenticationProvider에 위임.
3.  `AuthenticationProvider`는 실제 인증 정보를 검증하여 인증 처리.
    - loadUserByUsername(id)을 통해 UserDetailService에 사용자 객체를 요청.
    - 받아온 사용자 객체의 로그인 정보와 비교하여 실제 인증 처리.
4. `UserDetailService`의 loadUserByUsername() 메서드를 통해 repository(DB) 로부터 해당하는 id를 가진 사용자 객체(UserDetails)를 조회하여 반환한다.

### 6. 인증 관리자 - AuthenticationManager

<img width="591" alt="Untitled (6)" src="https://github.com/hgene0929/hgene0929/assets/90823532/4d66c4dd-f169-4f25-9eae-ef2bcf73ffeb">

- AuthenticationProvider 목록 중에서 인증 처리 요건에 맞는 AuthenticationProvider를 찾아 인증처리를 위임한다.
- 부모 ProviderManager를 설정하여 AuthenticationProvider를 계속 탐색할 수 있다.

### 7. 인증 처리자 - AuthenticationProvider

<img width="717" alt="Untitled (7)" src="https://github.com/hgene0929/hgene0929/assets/90823532/f08b2fb0-b10e-4a12-a4e8-a2919e04dde9">
