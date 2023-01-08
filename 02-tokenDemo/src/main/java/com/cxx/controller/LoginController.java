package com.cxx.controller;

import com.cxx.domain.ResponseResult;
import com.cxx.domain.User;
import com.cxx.service.LoginService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

/**
 * @author 陈喜喜
 * @date 2023-01-07 13:59
 */
@RestController
public class LoginController {
    @Resource
    private LoginService loginService;

    @PostMapping("/user/login")
    public ResponseResult login(@RequestBody User user){
        //登录
        System.out.println(user);
        return loginService.login(user);
    }

    @GetMapping("/user/logout")
    public ResponseResult logout(){
        //退出登录
        return loginService.logout();
    }
}
