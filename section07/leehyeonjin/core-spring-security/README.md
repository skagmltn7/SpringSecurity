## 해당 실습코드 목표

### proxyFactory를 활용한 실시간 메소드 보안 구현

> url 방식 인가처리 vs 메소드 방식 인가처리
> - url 방식 : 필터기반이므로, 실시간으로 DB에 등록된 url에 대한 보안 반영이 가능.
> - 메소드 방식 : AOP기반이므로, 실시간 보안 반영이 안됨.
> 
> 개선점 :
> - 메소드 보안은 스프링 시큐리티 초기화 시점에 보안 적용 대상 빈의 프록시 생성 및 어드바이스 적용이 이루어짐.
> - DB에 자원을 실시간으로 업데이트 하더라도 AOP가 바로 적용되지 않음.
> 
> 보안 메소드 실시간 적용 처리 과정 :
> 1. 메소드 보안 최초 설정 시 대상 빈의 프록시 객체 생성하고 메소드에 Advice 등록하여 AOP 적용.
> 2. MapBasedMethodSecurityMetadataSource에 자원 및 권한 정보 전달.
> 3. DefaultSingletonBeanRegistry로 실제 빈을 삭제하고 프록시 객체를 빈 참조로 등록.
> 4. 보안이 적용된 메소드 호출시 Advice가 작동한다.
> 5. 메소드 보안 해제 시 메소드에 등록되 Advice를 제거한다.
> 6. 메소드 보안 재설정 시 메소드에 등록된 Advice를 다시 등록한다.

전체목표 : 빈 후처리기에 의해 애플리케이션 초기화 DB에 등록된 메소드에 대한 보안처리를 하던 과정을 실시간으로 반영할 수 있도록 한다.

1. 사용자가 DB에 등록 및 제거한 메소드를 실시간으로 프록시 객체로 생성하여 보안에 반영한다.
* [DB에 등록된 메소드를 프록시 객체로 생성하여 보안을 반영하는 서비스 로직](./src/main/java/io/security/corespringsecurity/service/MethodSecurityService.java)

2. 스프링 시큐리티 설정파일에 MethodSecurityInterceptor에 대한 MethodSecurityMetadataSource를 주입해주기 위해 인터셉터를 커스텀하여 Advice(인가담당)의 역할을 하도록 한다.
* [Method 방식으로 프록시 객체를 가져오는 MethodSecurityInterceptor 커스텀](./src/main/java/io/security/corespringsecurity/security/interceptor/CustomMethodSecurityInterceptor.java)
* [스프링 시큐리티 설정 파일에 MethodSecurityInterceptor 빈등록](./src/main/java/io/security/corespringsecurity/security/configs/MethodSecurityConfig.java)

3. 테스트를 위한 컨트롤러 및 서비스를 구현한다.
* [AOP 테스트 컨트롤러](./src/main/java/io/security/corespringsecurity/aopsecurity/AopSecurityController.java)
* [AOP 테스트 서비스](./src/main/java/io/security/corespringsecurity/aopsecurity/AopLiveMethodService.java)
