package io.security.corespringsecurity.controller.user;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import io.security.corespringsecurity.domain.dto.AccountDto;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Controller
public class UserController {

	private final UserService userService;
	private final PasswordEncoder passwordEncoder;

	@GetMapping("/mypage")
	public String myPage() throws Exception {
		return "user/mypage";
	}

	@GetMapping("/users")
	public String createUser() {
		return "user/login/register";
	}

	@PostMapping("/users")
	public String createUser(AccountDto accountDto) {
		userService.createUser(accountDto);
		return "redirect:/";
	}
}
