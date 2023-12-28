package io.security.corespringsecurity.service.impl;

import java.util.List;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.security.corespringsecurity.domain.dto.RoleDto;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.repository.RoleRepository;
import io.security.corespringsecurity.service.RoleService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Service
public class RoleServiceImpl implements RoleService {

	private final RoleRepository roleRepository;
	ModelMapper mapper = new ModelMapper();

	@Override
	@Transactional
	public Role getRole(long id) {
		// 권한 테이블에서 id(PK)값을 통해 자원을 조회하고, 만약 존재하지 않는 id값이라면 새로운 권한 생성
		return roleRepository.findById(id).orElse(new Role());
	}

	@Override
	public List<Role> getRoleList() {
		// 권한 테이블에 존재하는 모든 권한 데이터들을 조회
		return roleRepository.findAll();
	}

	@Override
	@Transactional
	public void createRole(RoleDto roleDto) {
		// dto를 엔티티로 변환(엔티티로 변환하는 과정에서 ModelMapper 활용)
		Role role = mapper.map(roleDto, Role.class);

		// 새롭게 생성한 권한 데이터를 권한 테이블에 저장
		roleRepository.save(role);
	}

	@Override
	@Transactional
	public void deleteRole(long id) {
		// id(PK)값에 해당하는 권한 데이터를 권한 테이블에서 삭제
		roleRepository.deleteById(id);
	}
}
