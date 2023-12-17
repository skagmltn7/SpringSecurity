package io.security.corespringsecurity.domain.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccountDto {

	private String id;
	private String username;
	private String email;
	private int age;
	private String password;
	private List<String> roles;
}
