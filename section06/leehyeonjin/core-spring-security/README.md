## 해당 실습코드 목표

### method 방식 - 개요

> 서비스 계층의 인가처리 방식
> - 화면, 메뉴 단위가 아닌 기능 단위로 인가처리.
> - 메소드 처리 전,후로 보안 검사 수행하여 인가처리.
>
> AOP 기반으로 동작
> - 프록시와 어드바이스로 메소드 인가처리 수행.
>
> 보안 설정 방식
> - 어노테이션 권한 설정 방식 : @PreAuthorize("hasRole('USER')"), @PostAuthorize("hasRole('USER')"), @Secured("ROLE_USER").
> - 맵 기반 권한 설정 방식 : 맵 기반 방식으로 외부와 연동하여 메소드 보안 설정 구현.

---

### 어노테이션 권한 설정 - @PreAuthorize, @PostAuthorize, @Secured, @RolesAllowed

> 보안이 필요한 메소드에 설정한다.
> 
> @PreAuthorize, @PostAuthorize
> - SpEL 지원.
> - @PreAuthorize("hasRole('ROLE_USER') and (#account.username == principal.username)")
> - prePostAnnotationSecurityMetadataSource가 담당.
> 
> @Secured, @RolesAllowed
> - SpEL 미지원.
> - @Secured("ROLE_USER"), @RolesAllowed("ROLE_USER")
> - SecuredAnnotationSecurityMetadataSource, Jsr250MethodSecurityMetadataSource가 담당.
> 
> @EnableGlobalMethodSecurity(prePostEnabled = tru, securedEnabled = true)

<img width="687" alt="스크린샷 2023-12-17 오전 11 36 28" src="https://github.com/hgene0929/hgene0929/assets/90823532/2361ee9d-2e34-4cc8-8cbf-d28f53c54db8">

1. 메소드(기능) 단위에 어노테이션을 붙여 스프링 시큐리티 설정을 할 수 있도록 한다.
   - 컨트롤러 단위에 어노테이션을 통해 인가 기능을 부여.
        * [AOP용 컨트롤러 구현](./src/main/java/io/security/corespringsecurity/aopsecurity/AopSecurityController.java)
   - 각각의 보안 기능을 사용할 수 있도록 설정파일에서 기능을 켜줌.
        * [스프링 시큐리티 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)

---

### AOP Method 기반 DB 연동 - 주요 아키텍처 이해

<img width="234" alt="스크린샷 2023-12-17 오후 12 04 25" src="https://github.com/hgene0929/hgene0929/assets/90823532/89ff963e-5ecd-4e98-8be6-8e873940b58f">

> 인가 처리를 위한 초기화 과정과 진행
> - 초기화 과정
> 1. 초기화 시 전체 빈을 검사하면서 보안이 설정된 메소드가 있는지 탐색.
> 2. 빈의 프록시 객체를 생성.
> 3. 보안 메소드에 인가처리(권한심사) 기능을 하는 Advice를 등록.
> 4. 빈 참조시 실제 빈이 아닌 프록시 빈 객체를 참조.
> 
> - 진행과정
> 1. 메소드 호출 시 프록시 객체를 통해 메소드를 호출.
> 2. Advice가 등록되어 있다면 Advice를 작동하게 하여 인가 처리.
> 3. 권한 심사 통과하면 실제 빈의 메소드를 호출한다.

인가 처리를 위한 초기화 과정<br>
<img width="708" alt="스크린샷 2023-12-17 오후 12 13 06" src="https://github.com/hgene0929/hgene0929/assets/90823532/41335446-7b17-4885-af6d-9f187d4a6515">

> 1. MethodSecurityMetadataSourcePointcut을 통해 프록시 객체 생성 대상이 되는 메소드(메소드 단위로 권한 설정이 되어있는지) 탐색.
> 2. DefaultAdvisorAutoProxyCreator을 통해 보안 메소드가 설정된 빈에 대한 프록시 객체 생성.
> 3. MethodSecurityInterceptor을 통해 앞서 프록시 객체가 생성된 빈에 대한 어드바이스 등록.

인가 처리 초기화 과정 이후<br>
<img width="710" alt="스크린샷 2023-12-17 오후 12 17 27" src="https://github.com/hgene0929/hgene0929/assets/90823532/734a0af0-a759-4b28-9c57-2e88e57f3672">

> 3. 프록시 객체로부터 호출된 메소드를 찾아 Advice에 등록되어 있다면, MethodSecurityInterceptor을 호출하여 권한심사.
> 4. 권한심사를 통과한 경우, MethodSecurityInterceptor에 의해 해당 빈의 실제 객체 메소드 호출(권한심사 실패시 AccessDeniedException 발생).

1. 어노테이션 방식의 mehtod 기반 인가처리 부여 방식의 동작과정에 대해 파악한다.
    - 컨트롤러에서 해당 기능의 메소드를 호출.
        * [컨트롤러의 기능 추가](./src/main/java/io/security/corespringsecurity/controller/user/UserController.java)
    - 해당 기능(어노테이션 방식의 method 기반 인가처리 부여)을 메소드 단위에 부여.
        * [서비스의 비즈니스 로직](./src/main/java/io/security/corespringsecurity/service/impl/UserServiceImpl.java)
    - 스프링 시큐리티 설정파일에 앞서 작성한 인가방식을 등록.
        * [스프링 시큐리티 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)

---

### AOP Method 기반 DB 연동 - MapBasedSecurityMetadataSource

Filter 기반 url 방식 인가처리 vs AOP 기반 Method 방식 인가처리<br>
<img width="658" alt="스크린샷 2023-12-17 오후 12 33 02" src="https://github.com/hgene0929/hgene0929/assets/90823532/0a85dcba-50df-4f2e-b017-865c681cbb65">

Method 방식 - Map 기반 DB 연동<br>
<img width="360" alt="스크린샷 2023-12-17 오후 12 42 34" src="https://github.com/hgene0929/hgene0929/assets/90823532/8ff9d219-b7b5-43ef-9699-b465efe5e7d4"><br>
<img width="719" alt="스크린샷 2023-12-17 오후 12 45 19" src="https://github.com/hgene0929/hgene0929/assets/90823532/2532a8a7-49b8-438d-8578-426825009cf9">
<img width="701" alt="스크린샷 2023-12-17 오후 1 30 08" src="https://github.com/hgene0929/hgene0929/assets/90823532/86eed4a8-7fcf-4e9b-a96a-56c2f9b0c7dd">

> 어노테이션 설정 방식이 아닌 맵 기반으로 권한 설정.
> 
> 기본적인 구현이 완성되어 있고, DB로부터 자원과 권한정보를 맵핑한 데이터를 전달하면 베소드 방식의 인가 처리가 이루어지는 클래스.

1. DB로부터 자원-권한 정보가 맵핑된 데이터를 MapBasedMethodSecurityMetadaSource 클래스에 전달한다.
    - 맵 기반 인가처리를 지원하는 빈들을 등록하고 적용시키기 위한 스프링 시큐리티 설정파일 생성.
        * [스프링 시큐리티 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/MethodSecurityConfig.java)

2. Map 객체 형식으로 묶인 자원정보-권한정보를 맵핑해서 전달한다.
    - DB로부터 자원-권한 형태의 정보를 조회하여 바인딩한 Map 객체를 MapBasedMethodSecurityMetadataSource 생성자에 전달하여 초기화시 반영.
        * [DB로부터 조회해온 결과를 자원-권한 형태의 Map객체로 바인딩하여 넘겨주는 FactoryBean 커스텀](./src/main/java/io/security/corespringsecurity/security/factory/MethodResourcesMapFactoryBean.java)
    - 앞서 생성한 메소드 방식의 인가처리가 정상적으로 작동하는지 확인하기 위한 컨트롤러, 서비스 구현.
        * [Aop방식의 Map기반 메소드 방식 인가처리가 적용된 서비스를 호출하는 컨트롤러](./src/main/java/io/security/corespringsecurity/aopsecurity/AopSecurityController.java)
        * [Aop방식의 Map기반 메소드 방식 인가처리가 적용된 비즈니스 로직](./src/main/java/io/security/corespringsecurity/aopsecurity/AopMethodService.java)

---

### AOP Method 기반 DB 연동 - ProtectPointcutPostProcessor

> 메소드 방식의 인가처리를 위한 자원 및 권한정보 설정 시 자원에 포인트 컷 표현식을 사용할 수 있도록 지원하는 클래스.
> 
> 빈 후처리기로서 스프링 초기화 과정에서 빈들을 검사하여 빈이 가진 메소드 중에서 포인트 컷 표현식과 matching되는 클래스, 메소드, 권한 정보를 MapBasedMethodSecurityMetadataSource에 전달하여 인가처리가 되도록 제공되는 클래스.
> 
> DB 저장방식 :
> - method 방식 : io.security.service.OrderService.order : ROLE_USER
> - pointcut 방식 : execution(*io.security.service.*Service.*(..)) : ROLE_USER
> 
> 설정 클래스에서 빈 생성시 접근제한자가 package 범위로 되어 있기 때문에 리플렉션을 이용해 생성한다.

<img width="717" alt="스크린샷 2023-12-17 오후 2 00 01" src="https://github.com/hgene0929/hgene0929/assets/90823532/d944c05b-b782-4d72-a34e-5ba1cb77b67a">
<br>
<img width="715" alt="스크린샷 2023-12-17 오후 2 00 41" src="https://github.com/hgene0929/hgene0929/assets/90823532/3d92f56b-0674-4ef1-9443-9d37b04c44eb">

1. DB로부터 자원-권한 정보가 맵핑된 포인트 컷 표현식으로 작성해둔 데이터를 MapBasedMethodSecurityMetadaSource 클래스에 전달한다.
   - 미리 작성해둔 표현식과 동일한 자원들을 찾아 권한정보를 추출하여 넘겨줌.
      * [포인트컷 프로세서 구현](./src/main/java/io/security/corespringsecurity/security/processor/ProtectPointcutPostProcessor.java)
   - 맵 기반(포인트 컷 표현식) 인가처리를 지원하는 빈들을 등록하고 적용시키기 위한 스프링 시큐리티 설정파일 생성.
      * [스프링 시큐리티 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/MethodSecurityConfig.java)

2. Map 객체 형식으로 묶인 자원정보-권한정보를 맵핑해서 전달한다.
   - DB로부터 자원-권한 형태의 정보를 조회하여 바인딩한 Map 객체를 MapBasedMethodSecurityMetadataSource 생성자에 전달하여 초기화시 반영.
      * [DB로부터 조회해온 결과를 자원-권한 형태의 Map객체로 바인딩하여 넘겨주는 FactoryBean 커스텀](./src/main/java/io/security/corespringsecurity/security/factory/MethodResourcesMapFactoryBean.java)
   - 앞서 생성한 메소드 방식의 인가처리가 정상적으로 작동하는지 확인하기 위한 컨트롤러, 서비스 구현.
      * [Aop방식의 Map기반 메소드 방식 인가처리가 적용된 서비스를 호출하는 컨트롤러](./src/main/java/io/security/corespringsecurity/aopsecurity/AopSecurityController.java)
      * [Aop방식의 Map기반 메소드 방식 인가처리가 적용된 비즈니스 로직](./src/main/java/io/security/corespringsecurity/aopsecurity/AopPointcutService.java)
