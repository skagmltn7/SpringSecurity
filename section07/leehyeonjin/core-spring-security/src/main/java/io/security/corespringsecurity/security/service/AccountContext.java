package io.security.corespringsecurity.security.service;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import io.security.corespringsecurity.domain.entity.Account;
import lombok.Getter;

@Getter
public class AccountContext extends User {

	private Account account;

	public AccountContext(Account account, List<GrantedAuthority> roles) {
		super(account.getUsername(), account.getPassword(), roles);
		// 나중에 참조가능하도록 account를 멤버변수로 선언
		this.account = account;
	}
}
