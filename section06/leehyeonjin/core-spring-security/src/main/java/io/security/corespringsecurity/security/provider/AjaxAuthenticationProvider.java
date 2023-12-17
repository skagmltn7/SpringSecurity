package io.security.corespringsecurity.security.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import io.security.corespringsecurity.security.service.AccountContext;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class AjaxAuthenticationProvider implements AuthenticationProvider {

	private final UserDetailsService userDetailsService;
	private final PasswordEncoder passwordEncoder;

	@Override
	@Transactional
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// 구체적인 인증 처리 로직은 FormLogin 방식과 동일, 다만 인증 객체의 타입은 Ajax용 인증객체(AjaxAuthenticationToken)
		String loginId = authentication.getName();
		String password = (String) authentication.getCredentials();

		AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(loginId);

		if (!passwordEncoder.matches(password, accountContext.getPassword())) {
			throw new BadCredentialsException("Invalid password");
		}

		return new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.equals(AjaxAuthenticationToken.class);
	}
}
