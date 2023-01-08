package com.cxx;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author 陈喜喜
 * @date 2023-01-07 17:07
 */
public class test {
    @Test
    public void test(){
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        System.out.println(passwordEncoder.encode("lisi"));
        System.out.println(passwordEncoder.matches("lisi", "$2a$10$dRb89oOeT1h1GNDhCwjcW.FQxze3pFR9NKNVdam2ZQHiQLPNv1dVy"));
    }
}
