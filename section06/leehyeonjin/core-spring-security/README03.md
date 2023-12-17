## 해당 실습코드 목표

### 스프링 시큐리티 인가 개요

> 인가(Authorization) 프로세스 구현 - DB 연동
> - DB와 연동하여 자원 및 권한을 설정하고 제어함으로 동적 권한 관리가 가능하도록 한다.
> - 설정 클래스 소스에서 권한 관련 코드 모두 제거.
> - 관리자 시스템 구축
>   - 회원 관리 : 권한 부여.
>   - 권한 관리 : 권한 생성, 삭제.
>   - 자원 관리 : 자원 생성, 삭제, 수정, 권한 맵핑.
> - 권한 계층 구현
>   - url : url 요청시 인가 처리.
>   - method : method 호출시 인가 처리(method, pointcut).

---

### 관리자 시스템 - 권한 도메인, 서비스, 리포지토리 구성

url 방식 - 도메인 관계도<br>
<img width="718" alt="스크린샷 2023-12-16 오후 6 31 24" src="https://github.com/hgene0929/hgene0929/assets/90823532/f7fec4b4-29a2-4b9a-b14a-06e6db50dd75">
<br><br>
url 방식 - 테이블 관계도<br>
<img width="537" alt="스크린샷 2023-12-16 오후 6 33 45" src="https://github.com/hgene0929/hgene0929/assets/90823532/d83c379e-2200-4529-98a8-ff9e911e39f6">
<br><br>
1. 전체 목표 : 관리자 시스템을 구성하여 권한 부여, 생성, 삭제, 자원 관리 기능등에 대한 아키텍처를 생성하고, DB와 연동되어 실시간으로 작동할 수 있도록 한다.
<br><br>
2. 자원 관리 : 관리자가 자원(AntMatcher()의 파라미터)을 동적으로 적용할 수 있도록 하는 로직 구현.
    - 자원의 url(AntMatcher() 파라미터 패턴에 맞게), 리소스 타입(url인지 혹은 다른 타입으로 지정 가능), http 메서드(POST, GET, ..), 순서(해당 자원에 대한 보안적용 순서), 권한(해당 자원에 대한 접근이 가능한 권한)
   
    - 도메인 구성 : 자원 엔티티, dto 생성.
       * [자원 도메인](./src/main/java/io/security/corespringsecurity/domain/entity/Resources.java)
       * [자원 dto](./src/main/java/io/security/corespringsecurity/domain/dto/ResourcesDto.java)
    
    - 리포지토리 구성 : 자원 관련 DB 동작 구현.
       * [자원 리포지토리](./src/main/java/io/security/corespringsecurity/repository/ResourcesRepository.java)

    - 서비스 구성 : 자원 비즈니스 로직 구현(목록조회, 단건조회, 생성, 삭제).
       * [자원 서비스](./src/main/java/io/security/corespringsecurity/service/impl/ResourcesServiceImpl.java)

    - 컨트롤러 구성 : 자원 관련 클라이언트 요청 처리 로직 구현 및 뷰 반환(목록페이지, 등록, 자원상세 페이지에 필요한 권한목록조회, 상세페이지, 삭제).
       * [자원 컨트롤러](./src/main/java/io/security/corespringsecurity/controller/admin/ResourcesController.java)
<br><br>
3. 권한 관리 : 관리자가 권한을 등록 및 관리할 수 있도록 동적으로 DB에 저장 및 조회하는 로직 구현.
    - 권한의 이름(ROLE_권한명), 권한 설명(관리자, 매니저, ...)
   
    - 도메인 구성 : 권한 엔티티, dto 생성.
        * [권한 도메인](./src/main/java/io/security/corespringsecurity/domain/entity/Role.java)
        * [권한 dto](./src/main/java/io/security/corespringsecurity/domain/dto/RoleDto.java)

    - 리포지토리 구성 : 권한 관련 DB 동작 구현.
        * [권한 리포지토리](./src/main/java/io/security/corespringsecurity/repository/RoleRepository.java)

    - 서비스 구성 : 권한 비즈니스 로직 구현(목록조회, 단건조회, 생성, 삭제).
        * [권한 서비스](./src/main/java/io/security/corespringsecurity/service/impl/RoleServiceImpl.java)

    - 컨트롤러 구성 : 자원 관련 클라이언트 요청 처리 로직 구현 및 뷰 반환(목록페이지, 등록, 상세페이지, 삭제).
        * [권한 컨트롤러](./src/main/java/io/security/corespringsecurity/controller/admin/RoleController.java)
<br><br>
4. 회원 관리 : 일반사용자가 회원가입을 하고, 관리자가 회원 정보 관리 및 권한 관리할 수 있도록 하는 로직 구현.
   - 아이디, 비밀번호, 이메일, 나이(서비스에 가입된 다른 회원 정보 관리) 및 권한(서비스의 보안 정책에 따른 권한 관리).
   
   - 도메인 구성 : 회원 엔티티, dto 생성.
     * [회원 도메인](./src/main/java/io/security/corespringsecurity/domain/entity/Account.java)
     * [회원 dto](./src/main/java/io/security/corespringsecurity/domain/dto/AccountDto.java)

   - 리포지토리 구성 : 회원 관련 DB 동작 구현.
     * [회원 리포지토리](./src/main/java/io/security/corespringsecurity/repository/UserRepository.java)
    
   - 서비스 구성 : 회원 관련 비즈니스 로직 구현(목록조회, 단건조회, 생성, 업데이트, 삭제).
     * [회원 서비스](./src/main/java/io/security/corespringsecurity/service/impl/UserServiceImpl.java)
    
   - 컨트롤러 구성 : 회원 관련 일반사용자용(회원가입, 로그인), 회원관리자용(타회원 권한, 정보 관리) 컨트롤러 구현.
     * [회원관리자 컨트롤러](./src/main/java/io/security/corespringsecurity/controller/admin/AdminController.java)
     * [사용자 관리 컨트롤러](./src/main/java/io/security/corespringsecurity/controller/admin/UserManagerController.java)
<br><br>
5. 기타
   - 테스트 데이터 세팅.
     * [데이터 세팅 리스너](./src/main/java/io/security/corespringsecurity/security/listener/SetupDataLoader.java)
   
   - http 요청에 대한 타입을 미리 확인하기 위한 util 모듈 정의.
     * [http 헤더 확인용 util 모듈](./src/main/java/io/security/corespringsecurity/util/WebUtil.java)
<br><br>
6. 앞서 구현한 보안 로직이 스프링 시큐리티에 적용되어 동작할 수 있도록 함
   - 스프링 시큐리티 설정파일.
     * [스프링 시큐리티 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java) 

---

### 웹 기반 인가처리 DB 연동 - 주요 아키텍처 이해

스프링 시큐리티의 인가처리
<br>
<img width="510" alt="스크린샷 2023-12-16 오후 9 53 38" src="https://github.com/hgene0929/hgene0929/assets/90823532/88d9359e-94b9-423a-a2d4-b83972d465f0">
<br><br>
주요 아키텍처 이해
<br>
<img width="675" alt="스크린샷 2023-12-16 오후 9 56 20" src="https://github.com/hgene0929/hgene0929/assets/90823532/71cb3875-ca2d-4784-96f1-c1832d73a1c9">
<img width="710" alt="스크린샷 2023-12-16 오후 10 13 02" src="https://github.com/hgene0929/hgene0929/assets/90823532/2708566c-777c-4653-8cc4-b2c1961250ef">

> 1. Authentication을 통해 인증정보 보안 검증(user가 인증된 사용자인가?).
> <br><br>
> 2. FilterInvocation을 통해 요청 정보 확인(request(/user)는 어떤 자원에 접근을 시도하는가?).
> <br><br>
> 3. List<ConfigAttribute>를 통해 권한 정보 검증(hasRole("USER"))라는 필요한 권한을 가지고 있는가?).
> <br><br>
> 4. SecurityFilterInterceptor가 위 3가지 정보를 받아와 권한 정보 voter에게 넘겨 vote() 메서드의 파라미터로 메서드를 통해 권한 검증.

---

### 웹 기반 인가처리 DB 연동 - FilterInvocationSecurityMetadataSource

SecurityMetadataSource<br>
<img width="707" alt="스크린샷 2023-12-16 오후 10 17 01" src="https://github.com/hgene0929/hgene0929/assets/90823532/1aea5758-7285-4c99-b332-a1807e68259b">
<br><br>
FilterInvocationSecurityMetadataSource<br>
<img width="713" alt="스크린샷 2023-12-16 오후 10 19 22" src="https://github.com/hgene0929/hgene0929/assets/90823532/7acafa08-2146-483c-b4fd-7c981371d3e5">
<br><br>
url 방식 - Map 기반 DB 연동<br>
<img width="654" alt="스크린샷 2023-12-16 오후 10 44 52" src="https://github.com/hgene0929/hgene0929/assets/90823532/aeb36267-17c2-470d-b39d-70741e0ca09c">

1. FilterInvocation을 통해 알게된 요청정보(request(/user))와 List<ConfigAttribute>에서 가져온 권한정보(hasRole("USER"))를 각각 key-value 쌍으로 알맞게 바인딩한다.
    - .antMatchers("/mypage").hasRole("USER") 라는 시큐리티 설정파일의 고정 바인딩 방식 대신 동적으로 알맞은 요청정보에 권한정보가 Map 객체로 바인딩될 수 있도록 적용.
      * [Url용 FilterInvocationSecurityMetadataSource 커스텀 SecurityMetadataSource 생성](./src/main/java/io/security/corespringsecurity/security/metadatasource/UrlFilterInvocationSecurityMetadatsSource.java)
   
    - DB로부터 권한정보를 가져와 알맞은 요청정보에 바인딩할 만한 리스트를 생성하여 반환.
      * [DB와 권한정보를 위한 데이터를 동적으로 바인딩하기 위한 커스텀 서비스](./src/main/java/io/security/corespringsecurity/service/SecurityResourceService.java)
    
    - SecurityResourceService에서 동적으로 가져온 권한정보를 url(요청정보)와 바인딩하여 ResourcesMap 객체로 생성.
      * [Url용 ResourcesMapFactoryBean 커스텀](./src/main/java/io/security/corespringsecurity/security/factory/UrlResourcesMapFactoryBean.java)

2. 앞서 구현한 보안 로직이 스프링 시큐리티에 적용되어 동작할 수 있도록 함
    - 스프링 시큐리티 설정파일.
        * [스프링 시큐리티 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)

---

### 웹 기반 인가처리 실시간 반영하기

url 방식 - 인가처리 실시간 반영하기
<img width="639" alt="스크린샷 2023-12-16 오후 11 50 55" src="https://github.com/hgene0929/hgene0929/assets/90823532/77773c05-c744-4787-93fe-3ef280add1ce">

1. DB의 권한 혹은 자원정보가 업데이트 될 경우, 그에 해당하는 ResourcesMap 객체의 정보 또한 실시간으로 업데이트되도록 한다.
    - DB의 데이터 업데이트 사항을 ResourcesMap 객체에 실시간으로 반영.
        * [url용 FilterInvocationSecurityMetadataSource 커스텀](./src/main/java/io/security/corespringsecurity/security/metadatasource/UrlFilterInvocationSecurityMetadatsSource.java)
    - DB의 권한 및 자원 업데이트 정보를 실시간으로 반영하는 reload() 메서드를 필요한 컨트롤러에 적용.
       * [자원 컨트롤러](./src/main/java/io/security/corespringsecurity/controller/admin/ResourcesController.java)

---

### 인가처리 허용 필터 - PermitAllFilter 구현

url 방식 - PermitAllFilter 구현
<img width="711" alt="스크린샷 2023-12-17 오전 12 11 29" src="https://github.com/hgene0929/hgene0929/assets/90823532/c8bd0cf3-4f9a-4381-9cdf-6294effcd9de">

1. permitAll() 설정은 특정 자원에 대한 권한 심사를 하지 않겠다는 의미이므로, 해당 필터 요청이 호출될 경우 자원에 대한 권한심사를 건너뛴다.
      - 인증, 인가가 필요없는 자원들을 생성자로 받아와 사용자 요청정보와 바인딩.
         * [PermitAllFilter 커스텀](./src/main/java/io/security/corespringsecurity/security/filter/PermitAllFilter.java)
   
      - 앞서 생성한 필터를 스프링 시큐리티 설정파일에 등록.
         * [스프링 시큐리티 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)

---

### 계층 권한 적용하기 - RoleHierarchy

url 방식 - 계층 권한 적용하기
<img width="710" alt="스크린샷 2023-12-17 오전 12 12 22" src="https://github.com/hgene0929/hgene0929/assets/90823532/479c9c96-cc77-4650-8899-a963c933b7d7">

1. 권한 간의 상하관계를 부여하고, 상위 계층 권한을 가진 경우, 그 하위의 권한들도 모두 포함하도록 한다.
    - 도메인, 리포지토리, 서비스.
        * [도메인](./src/main/java/io/security/corespringsecurity/domain/entity/RoleHierarchy.java)
        * [리포지토리](./src/main/java/io/security/corespringsecurity/repository/RoleHierarchyRepository.java)
        * [서비스](./src/main/java/io/security/corespringsecurity/service/impl/RoleHierarchyServiceImpl.java)
        * [초기화시 DB에 테스트 데이터 삽입](./src/main/java/io/security/corespringsecurity/security/listener/SetupDataLoader.java)
   
   - 스프링 시큐리티 설정파일을 통해 계층 관련 빈등록.
        * [스프링 시큐리티 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)
   
   - 애플리케이션이 초기화될 시점에 필요한 권한의 계층관계를 계층 관련 컨포넌트에 주입.
        * [스프링 애플리케이션 이니셜라이져 구현](./src/main/java/io/security/corespringsecurity/security/init/SecurityInitializer.java) 

---

### 아이피 접속 제한하기 - CustomIpAddressVoter

<img width="591" alt="스크린샷 2023-12-17 오전 2 46 36" src="https://github.com/hgene0929/hgene0929/assets/90823532/2a1fd2f3-79f9-4fd4-b93e-1c9bb89cb1f8">

1. 요청 IP를 확인후, 허용된 IP라면 추가심의를 계속 진행시키고, 거부된 IP라면 예외를 발생시킨다.
    - 도메인, 리포지토리, 서비스.
        * [도메인](./src/main/java/io/security/corespringsecurity/domain/entity/RoleHierarchy.java)
        * [리포지토리](./src/main/java/io/security/corespringsecurity/repository/RoleHierarchyRepository.java)
        * [초기화시 DB에 테스트 데이터 삽입](./src/main/java/io/security/corespringsecurity/security/listener/SetupDataLoader.java)
    
    - DB에 저장된 모든 접근이 허용된 IP 주소 데이터를 조회하여 반환.
        * [DB와 인가관련 스프링 시큐리티를 동적으로 연동하기 위한 SecurityResourceService 클래스](./src/main/java/io/security/corespringsecurity/service/SecurityResourceService.java)
   
    - 인가 정책 심의자 클래스를 생성하여 접속 제한 IP인지 여부를 검사하여 인가 보류 혹은 예외 발생을 결정.
        * [인가 정책 심의자 Ip용 Voter 커스텀](./src/main/java/io/security/corespringsecurity/security/voter/IpAddressVoter.java)

    - 앞서 생성한 심의자를 스프링 시큐리티 파일에서 등록.
        * [스프링 시큐리티 설정파일](./src/main/java/io/security/corespringsecurity/security/configs/SecurityConfig.java)
