# 스프링 시큐리티 주요 아키텍처 이해( 인가 )

---

### 8. 인가 개념 및 필터 이해 - Authorization, FilterSecurityInterceptor

**Authorization**

- 인증을 받은 사용자가 특정 자원에 접근하려고 할 때, 자격이 있는지를 판단.
- 스프링 시큐리티가 지원하는 권한 계층 :
    - 웹 계층 : URL 요청에 따른 메뉴 혹은 화면단위의 레벨 보안.
    - 서비스 계층 : 화면 단위가 아닌 메소드 같은 기능 단위의 레벨 보안.
    - 도메인 계층(Access Control List, 접근 제어 목록) : 객체 단위의 레벨 보안.

---

**FilterSecurityInterceptor**

<img width="702" alt="Untitled (8)" src="https://github.com/hgene0929/hgene0929/assets/90823532/295a4d83-bbb5-45c3-865a-8b3075a5db0f">

- 마지막에 위치한 필터로서 인증된 사용자에 대하여 특정 요청의 승인/거부를 최종적으로 결정.
- 인증객체 없이 보호차원에 접근을 시도할 경우 AuthenticationException을 발생.
- 인증 후 자원에 접근 가능한 권한이 존재하지 않을 경우 AccessDeniedException 발생.
- 권한 제어 방식 중 HTTP 자원의 보안을 처리하는 필터.
- 권한 처리를 AccessDecisionManager에게 맡김.

### 9. 인가 결정 심의자 - AccessDicisionManan=ger, AccessDecisionVoter

<img width="703" alt="Untitled (9)" src="https://github.com/hgene0929/hgene0929/assets/90823532/3c55a2c2-8ea6-4f67-8805-d8ff52d274d1">

**AccessDecisionManager**

- 인증 정보, 요청 정보, 권한 정보를 이용해서 사용자의 자원접근을 허용할 것인지 거부할 것인지를 최종 결정하는 주체.
- 여러 개의 Voter들을 가질 수 있으며, Voter들로부터 접근 허용, 거부, 보류에 해당하는 각각의 값을 리턴받고 판단 및 결정.
- 최종 접근 거부 시 예외 발생.
- 접근 결정의 세가지 유형 :
    - AffirmativeBased :
        - 여러개의 Voter 클래스 중 하나라도 접근 허가로 결론을 내면 접근 허가로 판단.
    - ConsensusBased :
        - 다수표(승인 및 거부)에 의해 최종 결정을 판단한다,
        - 통수일 경우 기본은 접근 허가 이나 allowIfEqualGrantedDeniedDecisions을 false로 설정할 경우 접근 거부로 결정된다.
    - UnanimousBased :
        - 모든 Voter가 만장일치로 접근을 승인해야 하며 그렇지 않은 경우 접근을 거부한다.

---

**AccessDecisionVoter**

- Voter가 권한 부여 과정에서 판단하는 자료 :
    - Authentication : 인증 정보(user).
    - FilterInvocation : 요청 정보(antMatcher(”/user”))
    - ConfigAttributes : 권한 정보(hasRole(”USER”))
- 결정 방식 :
    - ACCESS_GRANTED : 접근허용(1).
    - ACCESS_DENIED : 접근 거부(-1).
    - ACCESS_ABSTAIN : 접근 보류(0).
        - Voter가 해당 타입의 요청에 대해 결정을 내릴 수 없는 경우.
