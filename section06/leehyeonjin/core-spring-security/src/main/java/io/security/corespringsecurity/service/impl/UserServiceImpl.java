package io.security.corespringsecurity.service.impl;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import io.security.corespringsecurity.domain.dto.AccountDto;
import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.repository.RoleRepository;
import io.security.corespringsecurity.repository.UserRepository;
import io.security.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Service
public class UserServiceImpl implements UserService {

	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final PasswordEncoder passwordEncoder;
	ModelMapper mapper = new ModelMapper();

	@Override
	@Transactional
	public void createUser(AccountDto accountDto) {
		// ModelMapper를 통해 소스(accountDto)에 담긴 데이터를 Account.class로 복사한다
		Account account = mapper.map(accountDto, Account.class);

		// PasswordEncoder를 활용하여 평문이었던 사용자 비밀번호를 암호화한다
		account.setPassword(passwordEncoder.encode(account.getPassword()));

		// 현재 사용자의 권한을 지정하기 위해 해당 권한을 권한명을 기준으로 조회(존재하지 않는 권한명이라면 예외 발생)
		// 이때, 처음 회원을 저장할 때는 기본값인 일반사용자로 지정(필요하다면 변경시 권한을 설정 및 추가하도록 로직 설정)
		Role role = roleRepository.findByRoleName("ROLE_USER")
			.orElseThrow(() -> new IllegalArgumentException("not-found role_name = " + "ROLE_USER"));

		// 앞서 조회해온 권한들을 회원 엔티티의 컬럼 타입에 알맞은 자료구조에 담아서 넘김
		Set<Role> roles = new HashSet<>();
		roles.add(role);
		account.setUserRoles(roles);

		// 사용자가 입력한 정보대로 회원 엔티티 저장
		userRepository.save(account);
	}

	@Override
	@Transactional
	public void modifyUser(AccountDto accountDto) {
		// ModelMapper를 통해 소스(accountDto)에 담긴 데이터를 Account.class로 복사한다
		Account account = mapper.map(accountDto, Account.class);

		// 사용자가 입력한 권한이 null이 아니라면 사용자가 입력한대로 권한 지정
		if (accountDto.getRoles() != null) {
			Set<Role> roles = new HashSet<>();
			accountDto.getRoles().forEach(roleName -> {
				Role role = roleRepository.findByRoleName(roleName)
					.orElseThrow(() -> new IllegalArgumentException("not-found role_name = " + roleName));
				roles.add(role);
			});
			account.setUserRoles(roles);
		}

		// 사용자가 입력한 비밀번호를 인코딩하여 저장
		account.setPassword(passwordEncoder.encode(accountDto.getPassword()));

		// 사용자가 입력한 정보대로 회원 엔티티 업데이트
		userRepository.save(account);
	}

	@Override
	public List<Account> getUserList() {
		return userRepository.findAll();
	}

	@Override
	@Transactional
	public AccountDto getUser(long id) {
		// 사용자가 입력한 id(PK)값을 기준으로 회원 엔티티 조회, 없다면 새롭게 생성
		Account account = userRepository.findById(id).orElse(new Account());

		// 조회된 결과 엔티티를 클라이언트에게 넘겨주기 위해 ModelMapper를 이용하여 dto로 바인딩
		AccountDto accountDto = mapper.map(account, AccountDto.class);

		// 조회된 회원 엔티티로부터 연관관계의 권한목록을 조회하여 회원엔티티의 컬럼에 맞는 자료구조로 변경
		List<String> roles = account.getUserRoles()
			.stream()
			.map(Role::getRoleName)
			.collect(Collectors.toList());
		accountDto.setRoles(roles);

		return accountDto;
	}

	@Override
	public void deleteUser(long id) {
		// id(PK)값에 해당하는 회원 데이터를 회원 테이블에서 삭제
		userRepository.deleteById(id);
	}

	@Override
	// 어노테이션 방식의 method 권한 부여
	@Secured("ROLE_MANAGER")
	public void order() {
		System.out.println("order");
	}
}
