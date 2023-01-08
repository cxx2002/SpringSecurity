package com.cxx.domain;

import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author 陈喜喜
 * @date 2023-01-06 17:04
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginUser implements UserDetails {
    private static final long serialVersionUID = 5189048561133591815L;

    private User user;
    private List<String> permissions;  // 权限信息集合
    @JSONField(serialize = false)  // 这样存入redis就会忽略这个成员变量，不会序列化到流再到redis当中
    private List<SimpleGrantedAuthority> authorities;  //这样就之会第一次会获取权限信息返回

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 这里这么做是因为，List<String> permissions是我们自己弄的权限信息，
        // 而SpringSecurity需要的权限信息是这个类型的List<SimpleGrantedAuthority> authorities

        if (this.authorities != null) {  // 这样就之会第一次会获取权限信息返回
            return this.authorities;
        }
        // 把permissions中String类型的权限信息封装成SimpleGrantedAuthority对象
        this.authorities = permissions.stream()
                .map(SimpleGrantedAuthority::new)  //等于.map(permission -> new SimpleGrantedAuthority(permission))
                .collect(Collectors.toList());
        return this.authorities;
    }

    public LoginUser(User user, List<String> permissions) {
        this.user = user;
        this.permissions = permissions;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUserName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
