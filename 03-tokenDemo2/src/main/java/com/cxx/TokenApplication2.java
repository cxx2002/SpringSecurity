package com.cxx;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * @author 陈喜喜
 * @date 2023-01-07 16:48
 */
@SpringBootApplication
@MapperScan("com.cxx.mapper")
public class TokenApplication2 {
    public static void main(String[] args) {
        ConfigurableApplicationContext run = SpringApplication.run(TokenApplication2.class, args);
    }
}
