package spring.corespringsecurity.domain.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.corespringsecurity.domain.Account;

public interface UserRepository extends JpaRepository<Account,Long> {
    Account findByUsername(String username);
}
