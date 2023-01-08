package com.cxx.filter;

import com.alibaba.fastjson.JSON;
import com.cxx.domain.LoginUser;
import com.cxx.domain.ResponseResult;
import com.cxx.utils.JwtUtil;
import com.cxx.utils.RedisCache;
import com.cxx.utils.WebUtils;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

/**
 * @author 陈喜喜
 * @date 2023-01-07 17:50
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    @Resource
    private RedisCache redisCache;

    //@SneakyThrows  //lombok的抛出所有Exception 相当于throws Exception
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //获取token
        String token = request.getHeader("token");
        if(!StringUtils.hasText(token)){
            //token都没有，直接放行
            filterChain.doFilter(request, response);
            return;//这里直接return是因为结束后续代码，也可以用if-else代替
            //直接放行后，SecurityContextHolder没有用户信息也没有一个认证的状态，所以会接着走后面的过滤器，再进行用户认证
        }

        //解析token
        String userId;
        try {
            Claims claims = JwtUtil.parseJWT(token);
            userId = claims.getSubject();  //通过token解析拿到userId
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("token 非法异常");
        }

        //从redis拿到用户信息
        String redisKey = "login:"+userId;
        LoginUser loginUser = redisCache.getCacheObject(redisKey);
        if(Objects.isNull(loginUser)){  //一般这是过期的情况
            //return new ResponseResult(403, "用户未登录");
            //这里不能return，只能是void方法，所以这里通常用一个工具类主动发一个响应给客户端
            WebUtils.renderString(response, JSON.toJSONString(new ResponseResult(403,"用户未登录或已过期")));
            return;
            //throw new RuntimeException("用户未登录");  //这样不会放回信息给客户端
        }

        //存入SecurityContextHolder
        //因为存在这，SpringSecurity每层过滤器都会先看这有没有用户信息并且是否是一个认证的状态，如果ok就直接全放行
        //TODO 获取权限信息封装到Authentication中  第三个参数就是存的权限信息的集合
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginUser, null, loginUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        filterChain.doFilter(request, response);//放行
    }
}
