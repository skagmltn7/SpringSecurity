package io.security.corespringsecurity.service.impl;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.security.corespringsecurity.domain.dto.ResourcesDto;
import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.repository.RoleRepository;
import io.security.corespringsecurity.service.ResourcesService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Service
public class ResourcesServiceImpl implements ResourcesService {

	private final ResourcesRepository resourcesRepository;
	private final RoleRepository roleRepository;
	ModelMapper mapper = new ModelMapper();

	@Override
	@Transactional
	public Resources getResources(long id) {
		// 자원 테이블에서 id(PK)값을 통해 자원을 조회하고, 만약 존재하지 않는 id값이라면 새로운 자원 생성
		// 새롭게 자원을 생성하는 경우, id만 자동으로 부여될 뿐 나머지 값들은 setter를 통해 업데이트 해주어야 함
		return resourcesRepository.findById(id).orElse(new Resources());
	}

	@Override
	public List<Resources> getResourcesList() {
		// 자원 테이블에 존재하는 모든 자원 데이터들을 조회, 이때 자원 출력 순서는 orderNum 컬럼을 기준으로 오름차순
		return resourcesRepository.findAll(Sort.by(Sort.Order.asc("orderNum")));
	}

	@Override
	@Transactional
	public void createResources(ResourcesDto resourcesDto) {
		// 사용자가 자원과 맵핑하고자 하는 권한을 사용자가 입력한 권한명을 기준으로 조회(존재하지 않는다면 예외 발생)
		Role role = roleRepository.findByRoleName(resourcesDto.getRoleName())
			.orElseThrow(() -> new IllegalArgumentException("not-found role_name = " + resourcesDto.getRoleName()));

		// 사용자가 입력한 권한명을 기준으로 조회한 권한 엔티티를 Set 자료구조에 삽입(자원 엔티티의 컬럼 데이터 타입에 부합하도록 Set 생성)
		Set<Role> roleSet = new HashSet<>();
		roleSet.add(role);

		// dto를 엔티티로 변환 후, 앞서 생성해둔 Set 자료구조 컬럼 데이터 삽입(엔티티로 변환하는 과정에서 ModelMapper 활용)
		Resources resources = mapper.map(resourcesDto, Resources.class);
		resources.setRoleSet(roleSet);

		// 새롭게 생성한 자원 데이터를 자원 테이블에 저장
		resourcesRepository.save(resources);
	}

	@Override
	@Transactional
	public void deleteResources(long id) {
		// id(PK)값에 해당하는 자원 데이터를 자원 테이블에서 삭제
		resourcesRepository.deleteById(id);
	}
}
