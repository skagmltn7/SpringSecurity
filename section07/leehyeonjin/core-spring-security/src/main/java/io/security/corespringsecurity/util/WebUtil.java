package io.security.corespringsecurity.util;

import javax.servlet.http.HttpServletRequest;

/**
 * http 요청에 대한 타입을 미리 확인하기 위한 util 모듈 정의
 */
public class WebUtil {
	// http 요청이 ajax 요청임을 확인하기 위해 클라이언트 서버와 약속한 헤더명 - 헤더값(아래의 문자열과 일치하다면 그 요청은 ajax 요청임)
	private static final String XML_HTTP_REQUEST = "XMLHttpRequest";
	private static final String X_REQUESTED_WITH = "X-Requested-With";

	// http 요청이 비동기인 경우 content type을 json으로 설정해주기 위해 필요한 값들을 상수로 미리 정의해둠
	private static final String CONTENT_TYPE = "Content-type";
	private static final String CONTENT_TYPE_JSON = "application/json";

	// http 요청이 ajax 요청임을 확인하는 메서드
	public static boolean isAjax(HttpServletRequest request) {
		return XML_HTTP_REQUEST.equals(request.getHeader(X_REQUESTED_WITH));
	}

	// http 요청이 비동기(json)임을 확인하는 메서드
	public static boolean isContentTypeJson(HttpServletRequest request) {
		return request.getHeader(CONTENT_TYPE).contains(CONTENT_TYPE_JSON);
	}
}
