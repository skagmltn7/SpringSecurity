package io.security.corespringsecurity.security.factory;

import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.security.corespringsecurity.service.SecurityResourceService;

public class UrlResourcesMapFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher, List<ConfigAttribute>>> {

	// DB로부터 가져온 데이터를 맵핑하는 작업을 하는 클래스 가져오기
	private SecurityResourceService securityResourceService;
	private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceMap;

	public void setSecurityResourceService(SecurityResourceService securityResourceService) {
		this.securityResourceService = securityResourceService;
	}

	@Override
	public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception {
		// ResourceMap(요청정보-권한정보 바인딩 객체)가 null이라면 초기화
		if (resourceMap == null) {
			init();
		}

		// ResourceMap을 반환
		return resourceMap;
	}

	private void init() {
		resourceMap = securityResourceService.getResourceList();
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
