package io.security.corespringsecurity.controller.admin;

import java.util.List;

import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import io.security.corespringsecurity.domain.dto.RoleDto;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.service.RoleService;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Controller
public class RoleController {

	private final RoleService roleService;

	@GetMapping("/admin/roles")
	public String getRoleList(Model model) throws Exception {
		List<Role> roleList = roleService.getRoleList();
		model.addAttribute("roles", roleList);
		return "admin/role/list";
	}

	@GetMapping("/admin/roles/register")
	public String viewRoles(Model model) throws Exception {
		RoleDto role = new RoleDto();
		model.addAttribute("role", role);
		return "admin/role/detail";
	}

	@PostMapping("/admin/roles")
	public String createRole(RoleDto roleDto) throws Exception {
		roleService.createRole(roleDto);
		return "redirect:/admin/roles";
	}

	@GetMapping("/admin/roles/{id}")
	public String getRole(@PathVariable Long id, Model model) throws Exception {
		Role role = roleService.getRole(id);

		ModelMapper mapper = new ModelMapper();
		RoleDto roleDto = mapper.map(role, RoleDto.class);
		model.addAttribute("role", roleDto);

		return "admin/role/detail";
	}

	@GetMapping("/admin/roles/delete/{id}")
	public String removeResources(@PathVariable Long id, Model model) throws Exception {
		roleService.deleteRole(id);
		return "redirect:/admin/resources";
	}
}
