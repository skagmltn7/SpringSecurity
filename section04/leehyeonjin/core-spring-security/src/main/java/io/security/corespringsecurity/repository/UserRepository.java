package io.security.corespringsecurity.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import io.security.corespringsecurity.domain.Account;

public interface UserRepository extends JpaRepository<Account, Long> {
	Optional<Account> findByUsername(String username);
}
