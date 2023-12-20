package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 유저네임으로 계정 정보 가져오기
        Account account = userRepository.findByUsername(username);

        if (account == null) {
            throw new UsernameNotFoundException("UsernameNotFoundException");
        }

        // 계정 정보에 저장된 role들을 grantedAuthority로 저장
        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(account.getRole()));

        // 계정에 roles를 부여하고 반환
        AccountContext accountContext = new AccountContext(account, roles);

        return accountContext;
    }
}
