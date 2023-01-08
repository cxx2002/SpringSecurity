package com.cxx.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.cxx.domain.LoginUser;
import com.cxx.domain.User;
import com.cxx.mapper.UserMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * @author 陈喜喜
 * @date 2023-01-06 16:44
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Resource
    private UserMapper userMapper;
    @Resource
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //查询数据库
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserName, username);
        User user = userMapper.selectOne(queryWrapper);
        //判断是否存在这个用户
        if (Objects.isNull(user)) {
            throw new RuntimeException("用户名或密码错误！");
        }
        //这里对admin用户特殊处理，admin用户在数据库的密码是明文，所以要手动加密再返回
        //而其他用户不需要，因为在数据库存的就是密文通过Bcrypt加密的密文，因为SecurityConfig配置了,如下，就默认是Bcrypt加密
        //@Bean
        //    public PasswordEncoder passwordEncoder(){
        //        return new BCryptPasswordEncoder();
        //    }
        if ("admin".equals(user.getUserName())) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        //ToDo 查询用户对应的权限信息返回  在数据库（RBAC权限模型）查出来 然后返回给前端进行vue组件路由（嘻嘻博客）
        //ToDo 然而嘻嘻博客的做法是防君子不防小人，用普通用户登录拿到token，带着token直接绕过前端去访问服务端就没有权限控制了
        //ToDo 解决办法就是在相应的api上加上这个注解@PreAuthorize("hasAuthority('test')")，test代表权限字符串
        List<String> list = Arrays.asList("test","admin"); // 这里简单模拟数据库查出来

        return new LoginUser(user, list);
        //返回给SpringSecurity框架的DaoAuthenticationProvider去做密码校验
        // （UserDetails的密码与Authentication的密码做比较）
        //  UserDetails存的是数据库查出来的密码      Authentication存的是前端输入过来的密码
    }
}
