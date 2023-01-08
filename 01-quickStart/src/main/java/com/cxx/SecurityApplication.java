package com.cxx;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * @author 陈喜喜
 * @date 2023-01-06 13:58
 */
@SpringBootApplication
public class SecurityApplication {

    public static void main(String[] args) {
        ConfigurableApplicationContext run = SpringApplication.run(SecurityApplication.class, args);
        //run.getBean(DefaultSecurityFilterChain.class)
        System.out.println("断点调试结束");
    }
}
