package spring.corespringsecurity.domain.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import spring.corespringsecurity.domain.Account;
import spring.corespringsecurity.domain.repository.UserRepository;
import javax.transaction.Transactional;

@Service("userService")
@RequiredArgsConstructor
public class UserServiceImpl implements UserService{

    private final UserRepository userRepository;
    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
