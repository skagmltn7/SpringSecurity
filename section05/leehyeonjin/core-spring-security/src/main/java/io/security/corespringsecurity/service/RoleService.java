package io.security.corespringsecurity.service;

import java.util.List;

import io.security.corespringsecurity.domain.dto.RoleDto;
import io.security.corespringsecurity.domain.entity.Role;

public interface RoleService {
	Role getRole(long id);

	List<Role> getRoleList();

	void createRole(RoleDto roleDto);

	void deleteRole(long id);
}
