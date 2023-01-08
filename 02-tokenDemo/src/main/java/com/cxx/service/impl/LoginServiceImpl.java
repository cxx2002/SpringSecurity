package com.cxx.service.impl;

import com.cxx.domain.LoginUser;
import com.cxx.domain.ResponseResult;
import com.cxx.domain.User;
import com.cxx.service.LoginService;
import com.cxx.utils.JwtUtil;
import com.cxx.utils.RedisCache;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * @author 陈喜喜
 * @date 2023-01-07 14:04
 *
 * Spring security 会将登录用户数据保存在 Session 中。但是，为了使用方便 Spring Security 在此基础上还做了一些改进，
 * 其中最主要的一个变化就是线程绑定。当用户登录成功后,Spring Security 会将登录成功的用户信息保存到 SecurityContextHolder 中。
 * 通过ThreadLocal+策略模式实现
 * SecurityContextHolder 中的数据保存默认景通过Threadlocal 来实现的，使用 Threadlocal 创建的变量只能被当前线程访问，
 * 不能被其他线程访问和修改，也就是用户数据和请求线程绑定在一起。当登录请求处理完毕后，Spring Security会将Security ContextHolder
 * 中的数据拿出来保存到 Session 中，同时将 SecurityContexHolder 中的数据清空。以后每当有请求到来时，Spring Security 就会先从
 * Session 中取出用户登录数据，保存到SecuritvContextHolder 中，方便在该请求的后续处理过程中使用，同时在请求结束时
 * 将 SecurityContextHolder 中的数据拿出来保存到 Session 中，然后将 Security SecurityContextHolder 中的数据清空，
 * 实际上 SecurityContextHolder 中存储是 SecurityContext. 在 SecurityContext 中存储是 Authentication.
 *
 * SecurityContextHolder将所有登录的用户信息都保存，每个登录的用户都可以通过SecurityContextHolder.getContext().getAuthentication()
 * 方式获取当前自己保存的用户信息多用户系统，比如典型的Web系统，整个生命周期可能同时有多个用户在使用。这时候应用需要保存多个
 * SecurityContext（安全上下文），需要利用ThreadLocal进行保存，每个线程都可以利用ThreadLocal获取其自己的SecurityContext，
 * 及安全上下文。
 */
@Service
public class LoginServiceImpl implements LoginService {
    @Resource
    private AuthenticationManager authenticationManager;
    @Resource
    private RedisCache redisCache;

    @Override
    public ResponseResult login(User user) {
        System.out.println("进入了login（），"+user.toString());
        //AuthenticationManager authenticate进行用户认证

        // 这里用前端传来的用户名和密码去new的时候会自动去和UserDetailsServiceImpl数据库查来的loginUser的用户名和密码去比对
        // 返回值是一个UsernamePasswordAuthenticationToken，调authenticate()方法，返回值是一个Authentication
        // 认证没成功就是null，成功了返回的authentication就存有数据库查出来的loginUser的用户信息
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword());
        Authentication authenticate = null;
        try {
            authenticate = authenticationManager.authenticate(authenticationToken);
        } catch (AuthenticationException e) {
            e.printStackTrace();
        }
        //如果认证不通过，给出对应的提示,返回的authenticate会为空
        if(Objects.isNull(authenticate)){
            throw new RuntimeException("登陆失败");
        }
        //如果认证通过了，使用userId生成一个jwt，jwt存到ResponseResult返回给客户端
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        String userId = loginUser.getUser().getId().toString();
        String jwt = JwtUtil.createJWT(userId);

        //把完整的用户信息存入redis，userId作为key，可以减少数据库的IO磁盘操作，提高效率
        HashMap<String, String> map = new HashMap<>();
        map.put("token", jwt);
        redisCache.setCacheObject("login:"+userId,loginUser,30, TimeUnit.MINUTES);
        redisCache.setCacheObject("token:"+userId,jwt,30, TimeUnit.MINUTES);

        return new ResponseResult<Map>(200,"登录成功",map);
    }

    @Override
    public ResponseResult logout() {
        //获取SecurityContextHolder中的用户id
        UsernamePasswordAuthenticationToken authentication =
                (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        Long userId = loginUser.getUser().getId();

        //输出redis中的值
        redisCache.deleteObject("login:" + userId);

        return new ResponseResult(200,"退出成功");
    }
}
