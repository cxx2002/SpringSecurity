package com.cxx;

import com.cxx.domain.User;
import com.cxx.mapper.UserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.annotation.Resource;
import java.util.List;

/**
 * @author 陈喜喜
 * @date 2023-01-06 16:27
 */
@SpringBootTest
public class MapperTest {
    @Resource
    private UserMapper userMapper;

    @Test
    public void testUserMapper(){
        List<User> userList = userMapper.selectList(null);
        System.out.println(userList);
    }

}
