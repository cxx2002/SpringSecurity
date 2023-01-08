package com.cxx;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * @author 陈喜喜
 * @date 2023-01-06 15:33
 */
@SpringBootApplication
@MapperScan("com.cxx.mapper")
public class TokenApplication {

    public static void main(String[] args) {
        ConfigurableApplicationContext run = SpringApplication.run(TokenApplication.class, args);
        System.out.println("断点调试结束");
    }
}
