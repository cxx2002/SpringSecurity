package com.cxx.service;

import com.cxx.domain.ResponseResult;
import com.cxx.domain.User;

/**
 * @author 陈喜喜
 * @date 2023-01-07 14:03
 */
public interface LoginService {
    ResponseResult login(User user);
}
