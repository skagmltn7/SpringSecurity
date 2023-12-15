package io.security.corespringsecurity.security.service;

import java.util.ArrayList;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// DB로 부터 해당 id를 가진 사용자 조회
		Optional<Account> account = userRepository.findByUsername(username);

		// 만약 조회된 사용자가 없다면 예외발생
		if (account.isEmpty()) {
			throw new UsernameNotFoundException("No user found with username: " + username);
		}

		// Collection 타입의 사용자 권한을 저장하는 목록을 생성한다
		ArrayList<GrantedAuthority> roles = new ArrayList<>();
		// ROLE_USER / ROLE_MANAGER / ROLE_ADMIN
		roles.add(new SimpleGrantedAuthority(account.get().getRole()));

		// 조회된 사용자가 있다면 최종적으로 UserDetails 타입의 사용자를 반환(이후 애플리케이션에서 참조하는데 사용되는 타입이다)
		// 직접 UserDetails를 상속받아 커스텀해서 사용할 수도 있고, 스프링 시큐리티에서 커스텀해둔 User 클래스를 사용할 수도 있다
		AccountContext accountContext = new AccountContext(account.get(), roles);

		return accountContext;
	}
}
