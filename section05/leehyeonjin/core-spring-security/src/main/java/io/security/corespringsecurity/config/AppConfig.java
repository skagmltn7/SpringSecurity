package io.security.corespringsecurity.config;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.security.configs.MethodSecurityConfig;
import io.security.corespringsecurity.service.SecurityResourceService;

@Configuration
@AutoConfigureBefore({ MethodSecurityConfig.class })
public class AppConfig {

	@Bean
	public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository, AccessIpRepository accessIpRepository) {
		SecurityResourceService securityResourceService = new SecurityResourceService(resourcesRepository, accessIpRepository);
		return securityResourceService;
	}
}
