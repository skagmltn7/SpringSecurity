package io.security.corespringsecurity.controller.user;

import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.domain.AccountDto;
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
		// ModelMapper를 통해 소스(accountDto)에 담긴 데이터를 Account.class로 복사한다
		ModelMapper mapper = new ModelMapper();
		Account account = mapper.map(accountDto, Account.class);

		// PasswordEncoder를 활용하여 평문이었던 사용자 비밀번호를 암호화한다
		account.setPassword(passwordEncoder.encode(account.getPassword()));

		userService.createUser(account);
		return "redirect:/";
	}
}
