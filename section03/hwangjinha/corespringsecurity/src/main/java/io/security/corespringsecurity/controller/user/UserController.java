package io.security.corespringsecurity.controller.user;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;

@RequiredArgsConstructor
@Controller
public class UserController {

	@Autowired
	private UserService userService;

	@Autowired
	private PasswordEncoder passwordEncoder;

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

		ModelMapper modelMapper = new ModelMapper();
		Account account = modelMapper.map(accountDto, Account.class);
		account.setPassword(passwordEncoder.encode(account.getPassword()));
		userService.createUser(account);

		return "redirect:/";
	}
}
