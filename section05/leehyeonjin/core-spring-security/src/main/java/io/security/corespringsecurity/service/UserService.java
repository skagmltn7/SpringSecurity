package io.security.corespringsecurity.service;

import java.util.List;

import io.security.corespringsecurity.domain.dto.AccountDto;
import io.security.corespringsecurity.domain.entity.Account;

public interface UserService {

	void createUser(AccountDto accountDto);

	void modifyUser(AccountDto accountDto);

	List<Account> getUserList();

	AccountDto getUser(long id);

	void deleteUser(long id);
}
