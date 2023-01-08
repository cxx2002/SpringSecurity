package com.cxx.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author 陈喜喜
 * @date 2023-01-06 15:35
 */
@RestController
public class HelloController {

    @GetMapping("/hello")
    @PreAuthorize("hasAuthority('test')")  // 要具有“test”权限信息才能访问
    public String hello(){
        return "Hello";
    }
}
