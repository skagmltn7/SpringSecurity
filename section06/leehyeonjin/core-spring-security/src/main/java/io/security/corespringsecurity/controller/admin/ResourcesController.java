package io.security.corespringsecurity.controller.admin;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import io.security.corespringsecurity.domain.dto.ResourcesDto;
import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadatsSource;
import io.security.corespringsecurity.service.ResourcesService;
import io.security.corespringsecurity.service.RoleService;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Controller
public class ResourcesController {

	private final ResourcesService resourcesService;
	private final RoleService roleService;
	private final UrlFilterInvocationSecurityMetadatsSource filterInvocationSecurityMetadatsSource;
	ModelMapper mapper = new ModelMapper();

	@GetMapping("/admin/resources")
	public String getResourcesList(Model model) throws Exception {
		List<Resources> resourcesList = resourcesService.getResourcesList();
		model.addAttribute("resources", resourcesList);
		return "admin/resource/list";
	}

	@PostMapping("/admin/resources")
	public String createResources(ResourcesDto resourcesDto) throws Exception {
		resourcesService.createResources(resourcesDto);
		filterInvocationSecurityMetadatsSource.reload();
		return "redirect:/admin/resources";
	}

	@GetMapping("/admin/resources/register")
	public String viewRoles(Model model) throws Exception {
		List<Role> roleList = roleService.getRoleList();
		model.addAttribute("roleList", roleList);

		ResourcesDto resources = new ResourcesDto();
		Set<Role> roleSet = new HashSet<>();
		roleSet.add(new Role());
		resources.setRoleSet(roleSet);
		model.addAttribute("resources", resources);

		return "admin/resource/detail";
	}

	@GetMapping("/admin/resources/{id}")
	public String getResources(@PathVariable Long id, Model model) throws Exception {
		List<Role> roleList = roleService.getRoleList();
		model.addAttribute("roleList", roleList);

		Resources resources = resourcesService.getResources(id);
		// 클라이언트에게 반환하기 위한 dto 형태로 조회 결과를 바인딩
		ResourcesDto resourcesDto = mapper.map(resources, ResourcesDto.class);
		model.addAttribute("resources", resourcesDto);

		return "admin/resource/detail";
	}

	@GetMapping("/admin/resources/delete/{id}")
	public String removeResources(@PathVariable Long id) throws Exception {
		resourcesService.deleteResources(id);
		filterInvocationSecurityMetadatsSource.reload();
		return "redirect:/admin/resources";
	}
}
