package io.security.corespringsecurity.service;


import io.security.corespringsecurity.domain.entity.Account;
import org.springframework.stereotype.Service;

@Service
public interface UserService {
    void createUser(Account account);
}
