package io.security.corespringsecurity.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import io.security.corespringsecurity.domain.entity.AccessIp;

public interface AccessIpRepository extends JpaRepository<AccessIp, Long> {

	AccessIp findByIpAddress(String ipAddress);
}
