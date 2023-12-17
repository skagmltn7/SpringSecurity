package io.security.corespringsecurity.controller.login;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;

@Controller
public class LoginController {

	@GetMapping("/login")
	public String login(
		@RequestParam(value = "error", required = false) String error,
		@RequestParam(value = "exception", required = false) String exception,
		Model model
	) {
		model.addAttribute("error", error);
		model.addAttribute("exception", exception);

		return "login";
	}

	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response) {
		// 전역 인증 객체 Authentication을 추출해온다
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		// Authentication 객체가 null이 아닌경우, 인증이 된 상태(로그인상태)이기 때문에 로그아웃을 처리한다
		if (authentication != null) {
			// 이때, 로그아웃은 SecurityContextLogoutHandler 인스턴스를 통해 수행한성
			new SecurityContextLogoutHandler().logout(request, response, authentication);
		}

		return "redirect:/login";
	}

	@GetMapping("/denied")
	public String accessDenied(@RequestParam(value = "exception", required = false) String exception, Principal principal, Model model) throws Exception {
		Account account = null;

		if (principal instanceof UsernamePasswordAuthenticationToken) {
			account = (Account) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();

		} else if(principal instanceof AjaxAuthenticationToken){
			account = (Account) ((AjaxAuthenticationToken) principal).getPrincipal();
		}

		model.addAttribute("username", account.getUsername());
		model.addAttribute("exception", exception);

		return "user/login/denied";
	}
}
