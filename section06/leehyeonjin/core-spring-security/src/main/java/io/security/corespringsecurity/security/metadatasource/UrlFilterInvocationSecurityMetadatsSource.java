package io.security.corespringsecurity.security.metadatasource;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.security.corespringsecurity.service.SecurityResourceService;

public class UrlFilterInvocationSecurityMetadatsSource implements FilterInvocationSecurityMetadataSource {

	// [요청정보-권한정보]를 key-value 형태로 저장하기 위한 자료구조 생성 및 초기화
	private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();
	private SecurityResourceService securityResourceService;

	public UrlFilterInvocationSecurityMetadatsSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap, SecurityResourceService securityResourceService) {
		this.requestMap = requestMap;
		this.securityResourceService = securityResourceService;
	}

	@Override
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
		// 파라미터로 들어온 객체(method 방식과 url 방식을 가지고 있음)로부터 url 방식의 요청정보 객체 추출
		HttpServletRequest request = ((FilterInvocation) object).getRequest();

		// DB에서 동적으로 RequestMap을 생성하여 아래의 주석의 코드와 같은 설정을 해주는 것
		// requestMap.put(new AntPathRequestMatcher("/mypage"), Arrays.asList(new SecurityConfig("ROLE_USER")));

		// 요청객체가 null이 아니라면, 요청정보에 알맞은 권한정보를 바인딩
		if (requestMap != null) {
			for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
				RequestMatcher matcher = entry.getKey();
				if (matcher.matches(request)) {
					return entry.getValue();
				}
			}
		}

		return null;
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		Set<ConfigAttribute> allAttibutes = new HashSet<>();

		for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
			allAttibutes.addAll(entry.getValue());
		}

		return allAttibutes;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

	public void reload() {
		// DB의 권한 및 자원 정보가 업데이트 될 경우 실시간으로 ResourcesMap 객체에 반영
		LinkedHashMap<RequestMatcher, List<ConfigAttribute>> reloadedMap = securityResourceService.getResourceList();

		// 새롭게 받아온 DB 업데이트 정보 iterator 객체로 추출
		Iterator<Map.Entry<RequestMatcher, List<ConfigAttribute>>> iterator = reloadedMap.entrySet().iterator();

		// 기존의 Map 객체 초기화
		requestMap.clear();

		// DB 업데이트 정보 객체에서 각각의 데이터를 바인딩하여 Map 객체 생성
		while (iterator.hasNext()) {
			Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = iterator.next();
			requestMap.put(entry.getKey(), entry.getValue());
		}
	}
}
