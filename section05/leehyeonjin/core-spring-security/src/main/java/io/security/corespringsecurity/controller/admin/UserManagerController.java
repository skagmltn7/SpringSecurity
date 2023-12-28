package io.security.corespringsecurity.controller.admin;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import io.security.corespringsecurity.domain.dto.AccountDto;
import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.service.RoleService;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Controller
public class UserManagerController {

	private final UserService userService;
	private final RoleService roleService;

	@GetMapping("/admin/accounts")
	public String getUsers(Model model) throws Exception {
		List<Account> accountList = userService.getUserList();
		model.addAttribute("accounts", accountList);
		return "admin/user/list";
	}

	@PostMapping("/admin/accounts")
	public String modifyUser(AccountDto accountDto) throws Exception {
		userService.modifyUser(accountDto);
		return "redirect:/admin/accounts";
	}

	@GetMapping("/admin/accounts/{id}")
	public String getUser(@PathVariable(value = "id") Long id, Model model) {
		AccountDto accountDto = userService.getUser(id);
		List<Role> roleList = roleService.getRoleList();

		model.addAttribute("account", accountDto);
		model.addAttribute("roleList", roleList);

		return "admin/user/detail";
	}

	@GetMapping("/admin/accounts/delete/{id}")
	public String removeUser(@PathVariable(value = "id") Long id, Model model) {
		userService.deleteUser(id);
		return "redirect:/admin/users";
	}
}
