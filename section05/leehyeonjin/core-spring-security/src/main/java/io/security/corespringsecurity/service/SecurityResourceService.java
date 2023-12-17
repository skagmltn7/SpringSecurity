package io.security.corespringsecurity.service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;

@Service
public class SecurityResourceService {

	private ResourcesRepository resourcesRepository;
	private AccessIpRepository accessIpRepository;

	public SecurityResourceService(ResourcesRepository resourcesRepository, AccessIpRepository accessIpRepository) {
		this.resourcesRepository = resourcesRepository;
		this.accessIpRepository = accessIpRepository;
	}

	public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList(){
		// 요청정보-권한정보의 형태를 저장할 Map 객체 생성
		LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();

		// DB에서 권한정보를 조회
		List<Resources> resourcesList = resourcesRepository.findAllResources();

		// 자원을 각각 살펴보며 알맞은 권한을 바인딩
		resourcesList.forEach(resources -> {
			List<ConfigAttribute> configAttributeList =  new ArrayList<>();
			resources.getRoleSet().forEach(role -> {
				configAttributeList.add(new SecurityConfig(role.getRoleName()));
				result.put(new AntPathRequestMatcher(resources.getResourceName()), configAttributeList);
			});
		});

		return result;
	}

	public LinkedHashMap<String, List<ConfigAttribute>> getMethodResourceList() {
		LinkedHashMap<String, List<ConfigAttribute>> result = new LinkedHashMap<>();
		List<Resources> resourcesList = resourcesRepository.findAllMethodResources();
		resourcesList.forEach(resources ->
			{
				List<ConfigAttribute> configAttributeList = new ArrayList<>();
				resources.getRoleSet().forEach(role -> {
					configAttributeList.add(new SecurityConfig(role.getRoleName()));
				});
				result.put(resources.getResourceName(), configAttributeList);
			}
		);
		return result;
	}

	public LinkedHashMap<String, List<ConfigAttribute>> getPointcutResourceList() {

		LinkedHashMap<String, List<ConfigAttribute>> result = new LinkedHashMap<>();
		List<Resources> resourcesList = resourcesRepository.findAllPointcutResources();
		resourcesList.forEach(resources ->
			{
				List<ConfigAttribute> configAttributeList = new ArrayList<>();
				resources.getRoleSet().forEach(role -> {
					configAttributeList.add(new SecurityConfig(role.getRoleName()));
				});
				result.put(resources.getResourceName(), configAttributeList);
			}
		);
		return result;
	}

	public List<String> getAccessIpList() {
		// DB에서 허용된 IP 데이터들을 모두 조회하여 반환
		List<String> accessIpList = accessIpRepository.findAll().stream()
			.map(accessIp -> accessIp.getIpAddress()).collect(Collectors.toList());
		return accessIpList;
	}
}
