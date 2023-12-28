package io.security.corespringsecurity.security.listener;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import io.security.corespringsecurity.domain.entity.AccessIp;
import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import io.security.corespringsecurity.repository.RoleRepository;
import io.security.corespringsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {

	private boolean alreadySetup = false;
	private final UserRepository userRepository;
	private final RoleRepository roleRepository;
	private final ResourcesRepository resourcesRepository;
	private final PasswordEncoder passwordEncoder;
	private final RoleHierarchyRepository roleHierarchyRepository;
	private final AccessIpRepository accessIpRepository;
	private static AtomicInteger count = new AtomicInteger(0);

	@Override
	@Transactional
	public void onApplicationEvent(ContextRefreshedEvent event) {
		// 이미 서버 기동 후, DB 초기 설정을 한번 했다면 건너뛰기
		if (alreadySetup) {
			return;
		}

		// 새롭게 서버 기동을 했다면, DB 초기 설정 후 플래그 처리
		setupSecurityResources();
		setupAccessIpData();
		alreadySetup = true;
	}

	private void setupSecurityResources() {
		// 테스트 권한 데이터 생성 및 DB에 저장
		Set<Role> roles = new HashSet<>();
		Role adminRole = createRoleIfNotFound("ROLE_ADMIN", "관리자");

		// 테스트 자원 데이터 생성 및 DB에 저장
		roles.add(adminRole);

		// 테스트 사용자 데이터 생성 및 DB에 저장
		Account account = createUserIfNotFound("admin", "pass", "admin@gmail.com", 10, roles);
		Role managerRole = createRoleIfNotFound("ROLE_MANAGER", "매니저권한");
		Role userRole = createRoleIfNotFound("ROLE_USER", "사용자권한");
		createRoleHierarchyIfNotFound(managerRole, adminRole);
		createRoleHierarchyIfNotFound(userRole, managerRole);
	}

	@Transactional
	public Role createRoleIfNotFound(String roleName, String roleDesc) {
		// DB의 권한 테이블로부터 해당 권한명의 데이터가 있는지 조회
		Optional<Role> optionalRole = roleRepository.findByRoleName(roleName);

		// 해당하는 권한 데이터가 존재하지 않을경우, 새로 생성
		Role role = optionalRole.orElseGet(() -> Role.builder()
			.roleName(roleName)
			.roleDesc(roleDesc)
			.build());

		return roleRepository.save(role);
	}

	@Transactional
	public Account createUserIfNotFound(String userName, String password, String email, int age, Set<Role> roleSet) {
		// DB의 권한 테이블로부터 해당 사용자명의 데이터가 있는지 조회
		Optional<Account> optionalAccount = userRepository.findByUsername(userName);

		// 해당하는 사용자 데이터가 존재하지 않을경우, 새로 생성
		Account account = optionalAccount.orElseGet(() -> Account.builder()
			.username(userName)
			.email(email)
			.age(age)
			.password(passwordEncoder.encode(password))
			.userRoles(roleSet)
			.build());

		return userRepository.save(account);
	}

	@Transactional
	public Resources createResourceIfNotFound(String resourceName, String httpMethod, Set<Role> roleSet, String resourceType) {
		// DB의 권한 테이블로부터 해당 자원명의 데이터가 있는지 조회
		Optional<Resources> optionalResources = resourcesRepository.findByResourceNameAndHttpMethod(resourceName, httpMethod);

		// 해당하는 자원 데이터가 존재하지 않을경우, 새로 생성
		Resources resources = optionalResources.orElseGet(() -> Resources.builder()
			.resourceName(resourceName)
			.roleSet(roleSet)
			.httpMethod(httpMethod)
			.resourceType(resourceType)
			.orderNum(count.incrementAndGet())
			.build());

		return resourcesRepository.save(resources);
	}

	@Transactional
	public void createRoleHierarchyIfNotFound(Role childRole, Role parentRole) {
		RoleHierarchy roleHierarchy = roleHierarchyRepository.findByChildName(parentRole.getRoleName());
		if (roleHierarchy == null) {
			roleHierarchy = RoleHierarchy.builder()
				.childName(parentRole.getRoleName())
				.build();
		}
		RoleHierarchy parentRoleHierarchy = roleHierarchyRepository.save(roleHierarchy);

		roleHierarchy = roleHierarchyRepository.findByChildName(childRole.getRoleName());
		if (roleHierarchy == null) {
			roleHierarchy = RoleHierarchy.builder()
				.childName(childRole.getRoleName())
				.build();
		}
		RoleHierarchy childRoleHierarchy = roleHierarchyRepository.save(roleHierarchy);
		childRoleHierarchy.setParentName(parentRoleHierarchy);
	}

	private void setupAccessIpData() {
		AccessIp byIpAddress = accessIpRepository.findByIpAddress("0:0:0:0:0:0:0:1");
		if (byIpAddress == null) {
			AccessIp accessIp = AccessIp.builder()
				.ipAddress("0:0:0:0:0:0:0:1")
				.build();
			accessIpRepository.save(accessIp);
		}
	}
}
