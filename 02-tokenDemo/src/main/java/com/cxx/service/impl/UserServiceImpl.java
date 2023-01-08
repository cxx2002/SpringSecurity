package com.cxx.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.cxx.domain.User;
import com.cxx.service.UserService;
import com.cxx.mapper.UserMapper;
import org.springframework.stereotype.Service;

/**
* @author 陈喜喜
* @description 针对表【sys_user(用户表)】的数据库操作Service实现
* @createDate 2023-01-06 16:12:00
*/
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User>
    implements UserService{

}




