package com.cxx.handler;

import com.alibaba.fastjson.JSON;
import com.cxx.domain.ResponseResult;
import com.cxx.utils.WebUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    // 授权时出现异常
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        accessDeniedException.printStackTrace();
        ResponseResult result = new ResponseResult(401,"授权时出现问题");
        //响应给前端
        WebUtils.renderString(response, JSON.toJSONString(result));
    }
}
