package com.cxx.config;

import com.cxx.filter.JwtAuthenticationTokenFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.Resource;

/**
 * @author 陈喜喜
 * @date 2023-01-06 17:29
 *
 * 只有加了@EnableGlobalMethodSecurity(prePostEnabled=true)
 * 那么在上面使用的 @PreAuthorize(“hasAuthority(‘admin’)”)才会生效
 * 要改变默认表单登录页面,前端写好页面发请求,后端在对应的service层调用authenticate()这些就可以了,例:本项目的LoginServiceImpl
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Resource
    private JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;
    @Resource
    private AccessDeniedHandler accessDeniedHandler;
    @Resource
    private AuthenticationEntryPoint authenticationEntryPoint;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //关闭csrf  前后端分离的项目不存在csrf攻击  不关还要去校验csrf_token
                .csrf().disable()
                //不通过Session获取SecurityContext
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                // 对于登录接口 允许匿名访问  匿名访问就算没登陆认证可以访问  登录认证了就不可以访问
                .antMatchers("/user/login").anonymous()
                //.antMatchers("/hello").permitAll    // 这个是允许所有访问
                .antMatchers("/hello").hasAuthority("test")//等于@PreAuthorize("hasAuthority('test')")
                // 除上面外的所有请求全部需要鉴权认证
                .anyRequest().authenticated();

        //配置jwt过滤器
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);

        //配置异常处理器
        http.exceptionHandling()
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler);

        http.logout().disable();

        //允许跨域  SpringSecurity的跨域配置
        http.cors();
    }
}
