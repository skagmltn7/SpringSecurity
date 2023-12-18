package io.security.corespringsecurity.service.impl;

import java.util.Iterator;
import java.util.List;

import org.springframework.stereotype.Service;

import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import io.security.corespringsecurity.service.RoleHierarchyService;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class RoleHierarchyServiceImpl implements RoleHierarchyService {

	private final RoleHierarchyRepository roleHierarchyRepository;

	@Override
	public String findAllHierarchy() {
		List<RoleHierarchy> roleHierarchyList = roleHierarchyRepository.findAll();

		Iterator<RoleHierarchy> iterator = roleHierarchyList.iterator();
		StringBuffer concatedRoles = new StringBuffer();

		while (iterator.hasNext()) {
			RoleHierarchy model = iterator.next();
			if (model.getParentName() != null) {
				concatedRoles.append(model.getParentName().getChildName());
				concatedRoles.append(" > ");
				concatedRoles.append(model.getChildName());
				concatedRoles.append("\n");
			}
		}

		return concatedRoles.toString();
	}
}
