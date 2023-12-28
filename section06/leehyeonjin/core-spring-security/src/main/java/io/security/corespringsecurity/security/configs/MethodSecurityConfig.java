package io.security.corespringsecurity.security.configs;

import java.util.Objects;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

import io.security.corespringsecurity.security.factory.MethodResourcesMapFactoryBean;
import io.security.corespringsecurity.security.interceptor.CustomMethodSecurityInterceptor;
import io.security.corespringsecurity.security.processor.ProtectPointcutPostProcessor;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

@RequiredArgsConstructor
@Configuration
// 메소드 및 어노테이션 보안 방식을 사용할 수 있도록 해당 기능을 활성화
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
// GlobalMethodSecurityConfiguration : 메소드 보안 활성화 및 관련 초기화 작업시 필요한 빈 생성, 인가처리에 필요한 기능
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

	private final SecurityResourceService securityResourceService;

	@Override
	protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
		// 맵 기반으로 메소드 인가처리를 할 수 있는 클래스를 생성하여 반환
		return mapBasedMethodSecurityMetadataSource();
	}

	@Bean
	public MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource() {
		// DB로부터 얻어온 Map 객체를 생성자로 주입한 MapBasedMethodSecurityMetadataSource 생성 및 빈등록
		return new MapBasedMethodSecurityMetadataSource(methodResourcesMapFactoryBean().getObject());
	}

	@Bean
	public MethodResourcesMapFactoryBean methodResourcesMapFactoryBean() {
		// DB로부터 자원을 받아오기 위한 빈과 인가처리 방식(메소드)을 setter로 주입받은 커스텀 FactoryBean 빈등록
		MethodResourcesMapFactoryBean methodResourcesMapFactoryBean = new MethodResourcesMapFactoryBean();
		methodResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
		methodResourcesMapFactoryBean.setResourceType("method");
		return methodResourcesMapFactoryBean;
	}

	@Bean
	@Profile("pointcut")
	public MethodResourcesMapFactoryBean pointcutMethodResourcesMapFactoryBean() {
		// DB로부터 자원을 받아오기 위한 빈과 인가처리 방식(메소드)을 setter로 주입받은 커스텀 FactoryBean 빈등록
		// 이때 DB로부터 받아오는 자원정보는 포인트 컷 표현식이 사용됨
		MethodResourcesMapFactoryBean methodResourcesMapFactoryBean = new MethodResourcesMapFactoryBean();
		methodResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
		methodResourcesMapFactoryBean.setResourceType("pointcut");
		return methodResourcesMapFactoryBean;
	}

	@Bean
	@Profile("pointcut")
	public ProtectPointcutPostProcessor protectPointcutPostProcessor() throws Exception {
		// 빈 후처리기 : 빈이 생성된 이전, 이후에 해당 빈에 대한 설정 조작
		// 자원정보가 포인트 컷 표현식에 해당하는지 검증 후, 포함된다면 프록시 객체 생성
		// 미리 작성해둔 표현식과 동일한 자원들을 찾아 권한정보를 추출하여 넘겨줌
		ProtectPointcutPostProcessor protectPointcutPostProcessor = new ProtectPointcutPostProcessor(mapBasedMethodSecurityMetadataSource());
		protectPointcutPostProcessor.setPointcutMap(pointcutMethodResourcesMapFactoryBean().getObject());
		return protectPointcutPostProcessor;
	}

	@Bean
	public CustomMethodSecurityInterceptor customMethodSecurityInterceptor(MapBasedMethodSecurityMetadataSource methodSecurityMetadataSource) {
		CustomMethodSecurityInterceptor customMethodSecurityInterceptor = new CustomMethodSecurityInterceptor();
		customMethodSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
		customMethodSecurityInterceptor.setAfterInvocationManager(afterInvocationManager());
		customMethodSecurityInterceptor.setSecurityMetadataSource(methodSecurityMetadataSource);
		RunAsManager runAsManager = runAsManager();
		if (runAsManager != null) {
			customMethodSecurityInterceptor.setRunAsManager(runAsManager);
		}
		return customMethodSecurityInterceptor;
	}

	@Bean
	public AccessDecisionVoter<? extends Object> roleVoter() {
		RoleHierarchyVoter roleHierarchyVoter = new RoleHierarchyVoter(roleHierarchy());
		return roleHierarchyVoter;
	}

	@Bean
	public RoleHierarchyImpl roleHierarchy() {
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		return roleHierarchy;
	}
}
