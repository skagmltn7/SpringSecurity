package io.security.corespringsecurity.security.service;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import io.security.corespringsecurity.domain.Account;
import lombok.Data;

@Data
public class AccountContext extends User {

	private Account account;

	public AccountContext(Account account, ArrayList<GrantedAuthority> roles) {
		super(account.getUsername(), account.getPassword(), roles);
		// 나중에 참조가능하도록 account를 멤버변수로 선언
		this.account = account;
	}
}
