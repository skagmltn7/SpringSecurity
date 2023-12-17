package io.security.corespringsecurity.security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class PermitAllFilter extends FilterSecurityInterceptor {

	private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
	private boolean observeOncePerRequest = true;

	// 사용자 요청정보와 권한, 인증이 필요없는 자원들을 바인딩하기 위한 RequestMatcher객체 리스트 생성 및 초기화
	private List<RequestMatcher> permitAllRequestMatchers = new ArrayList<>();

	// 생성자를 통해 인증이나 인가가 필요없는 자원들을 파라미터로 받아옴
	public PermitAllFilter(String... permitAllResources) {
		for(String resource : permitAllResources){
			permitAllRequestMatchers.add(new AntPathRequestMatcher(resource));
		}
	}

	// 실제 인가처리를 하기전 인증, 인가가 필요없음을 정텀
	@Override
	protected InterceptorStatusToken beforeInvocation(Object object) {
		boolean permitAll = false;
		HttpServletRequest request = ((FilterInvocation) object).getRequest();
		for(RequestMatcher requestMatcher : permitAllRequestMatchers){
			if(requestMatcher.matches(request)){
				permitAll = true;
				break;
			}
		}

		if(permitAll){
			return null;
		}

		return super.beforeInvocation(object);
	}

	// 실제 인가처리 과정으로 넘겨줌
	@Override
	public void invoke(FilterInvocation fi) throws IOException, ServletException {
		if ((fi.getRequest() != null)
			&& (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
			&& observeOncePerRequest) {
			// filter already applied to this request and user wants us to observe
			// once-per-request handling, so don't re-do security checking
			fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
		}
		else {
			// first time this request being called, so perform security checking
			if (fi.getRequest() != null && observeOncePerRequest) {
				fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
			}

			InterceptorStatusToken token = beforeInvocation(fi);

			try {
				fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
			}
			finally {
				super.finallyInvocation(token);
			}

			super.afterInvocation(token, null);
		}
	}

	// 인증, 인가가 필요없는 자원들과 사용자 요청정보를 각각 바인딩
	private void createPermitAllPattern(String... permitAllPattern) {
		for (String pattern : permitAllPattern) {
			permitAllRequestMatchers.add(new AntPathRequestMatcher(pattern));
		}
	}
}
