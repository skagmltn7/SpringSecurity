package io.security.corespringsecurity.service;

import java.util.List;

import io.security.corespringsecurity.domain.dto.ResourcesDto;
import io.security.corespringsecurity.domain.entity.Resources;

public interface ResourcesService {
	Resources getResources(long id);

	List<Resources> getResourcesList();

	void createResources(ResourcesDto resourcesDto);

	void deleteResources(long id);
}
