package io.security.corespringsecurity.security.voter;

import java.util.Collection;
import java.util.List;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import io.security.corespringsecurity.service.SecurityResourceService;

public class IpAddressVoter implements AccessDecisionVoter<Object> {

	private SecurityResourceService securityResourceService;

	public IpAddressVoter(SecurityResourceService securityResourceService) {
		this.securityResourceService = securityResourceService;
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		return true;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return true;
	}

	@Override
	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
		// 인증객체 정보로부터 부가정보(details)를 추출하여 그 안에서 요청의 IP 정보를 추출
		WebAuthenticationDetails details = (WebAuthenticationDetails)authentication.getDetails();
		String remoteAddress = details.getRemoteAddress();

		// 접근이 허용된 IP 데이터를 DB로부터 조회
		List<String> accessIpList = securityResourceService.getAccessIpList();

		int result = ACCESS_DENIED;

		// DB에 있는 접속이 허용된 IP와 요청의 IP가 동일하다면 심사 보류
		for (String ipAddress : accessIpList) {
			if (remoteAddress.equals(ipAddress)) {
				return ACCESS_ABSTAIN;
			}
		}

		// DB에 있는 접속이 허용된 IP와 요청의 IP가 서로 다르면 예외 발생
		if (result == ACCESS_DENIED) {
			throw new AccessDeniedException("Invalid IpAddress");
		}

		return result;
	}
}
