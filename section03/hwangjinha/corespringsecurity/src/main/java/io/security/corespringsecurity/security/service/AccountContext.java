package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Data
public class AccountContext extends User {

    private final Account account;
    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        // 상위 user 객체에 username, password authorities를 저장하고 계정정보를 갖는다.
        super(account.getUsername(), account.getPassword(), authorities);
        this.account = account;
    }
}
