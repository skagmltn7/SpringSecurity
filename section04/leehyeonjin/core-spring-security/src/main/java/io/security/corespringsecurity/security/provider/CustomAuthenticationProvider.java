package io.security.corespringsecurity.security.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

	private final UserDetailsService userDetailsService;
	private final PasswordEncoder passwordEncoder;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// 사용자 입력 id, pw가 들어있는 authentication 객체로 부터 인증정보 추출
		String username = authentication.getName();
		String password = (String)authentication.getCredentials();

		// DB로부터 사용자를 조회해온 후, 상세한 인증절차 수행
		AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(username);

		// 패스워드가 일치하지 않는 경우
		if (!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
			throw new BadCredentialsException("Invalid password");
		}

		// id,pw 이외의 부가정보를 로그인시 입력받고, 해당 데이터 또한 인증시 활용
		FormWebAuthenticationDetails details = (FormWebAuthenticationDetails)authentication.getDetails();
		String secretKey = details.getSecretKey();
		if (secretKey == null || !"secret".equals(secretKey)) {
			throw new InsufficientAuthenticationException("Invalid details");
		}

		// 최종적인 검증이 성공된 이후, 인증토큰 생성(비밀번호는 보안을 위해 토큰에 담지 않음)
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
			accountContext.getAccount(), null, accountContext.getAuthorities()
		);

		return authenticationToken;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// 파라미터로 주어지는 authentication과 현재 클래스가 사용하고자하는 토큰의 타입이 일치할 떄, 해당 Provider 인증처리를 하도록 설정
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
