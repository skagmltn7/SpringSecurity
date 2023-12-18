package io.security.corespringsecurity.security.factory;

import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;

import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MethodResourcesMapFactoryBean implements FactoryBean<LinkedHashMap<String, List<ConfigAttribute>>> {

	// DB로부터 가져온 데이터를 맵핑하는 작업을 하는 클래스 가져오기
	private SecurityResourceService securityResourceService;
	private String resourceType;

	public void setResourceType(String resourceType) {
		this.resourceType = resourceType;
	}

	public void setSecurityResourceService(SecurityResourceService securityResourceService) {
		this.securityResourceService = securityResourceService;
	}

	private LinkedHashMap<String, List<ConfigAttribute>> resourcesMap;

	public void init() {
		// DB로부터 메소드 방식의 자원을 맵핑하여 조회
		if ("method".equals(resourceType)) {
			resourcesMap = securityResourceService.getMethodResourceList();
		}
		// DB로부터 메소드 방식의 자원을 맵핑하여 조회(이때, 해당 자원은 포인트 컷으로 작성됨)
		else if ("pointcut".equals(resourceType)) {
			resourcesMap = securityResourceService.getPointcutResourceList();
		}
	}

	@Override
	public LinkedHashMap<String, List<ConfigAttribute>> getObject() {
		// ResourceMap(요청정보-권한정보 바인딩 객체)가 null이라면 초기화
		if (resourcesMap == null) {
			init();
		}

		// ResourceMap을 반환
		return resourcesMap;
	}

	@Override
	public Class<?> getObjectType() {
		// ResourceMap의 타입은 LinkedHashMap으로 설정
		return LinkedHashMap.class;
	}

	@Override
	public boolean isSingleton() {
		// ResourceMap은 싱글톤으로 생성하여 메모리에 단하나만 존재하도록 함
		return true;
	}
}
