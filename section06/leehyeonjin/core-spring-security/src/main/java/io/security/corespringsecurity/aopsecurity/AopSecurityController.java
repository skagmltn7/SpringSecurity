package io.security.corespringsecurity.aopsecurity;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import io.security.corespringsecurity.domain.dto.AccountDto;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Controller
public class AopSecurityController {

	private final AopMethodService aopMethodService;
	private final AopPointcutService aopPointcutService;
	private final AopLiveMethodService aopLiveMethodService;

	@GetMapping("/preAuthorize")
	// @PreAuthorize 어노테이션을 통해 인가승인을 위한 규칙을 적용
	@PreAuthorize("hasRole('ROLE_USER') and #accountDto.username == principal.username")
	public String preAuthorize(AccountDto accountDto, Model model, Principal principal) {
		model.addAttribute("method", "Success @PreAuthorize");
		return "aop/method";
	}

	@GetMapping("/methodSecured")
	public String methodSecured(Model model) {
		aopMethodService.methodSecured();
		model.addAttribute("method", "Success MethodSecured");
		return "aop/method";
	}

	@GetMapping("/pointcutSecured")
	public String pointcutSecured(Model model) {
		aopPointcutService.notSecured();
		aopPointcutService.pointcutSecured();
		model.addAttribute("method", "Success PointcutSecured");
		return "aop/method";
	}

	@GetMapping("/liveMethodSecured")
	public String lineMethodSecured(Model model) {
		aopLiveMethodService.liveMethodSecured();
		model.addAttribute("method", "Success LiveMethodSecured");
		return "aop/method";
	}
}
