package spring.corespringsecurity.controller.user;

import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import spring.corespringsecurity.domain.Account;
import spring.corespringsecurity.domain.AccountDto;
import spring.corespringsecurity.domain.service.UserService;

@Controller
@RequiredArgsConstructor
public class UserController {

	private final PasswordEncoder passwordEncoder;
	private final UserService userService;

	@GetMapping("/users")
	public String createUser() throws Exception {
		return "user/login/register";
	}

	@PostMapping("/users")
	public String createUser(AccountDto accountDto){
		ModelMapper modelMapper = new ModelMapper();
		Account account = modelMapper.map(accountDto, Account.class);
		account.setPassword(passwordEncoder.encode(account.getPassword()));
		userService.createUser(account);
		return "redirect:/";
	}

	@GetMapping("/mypage")
	public String myPage() throws Exception{
		return "user/mypage";
	}

}
