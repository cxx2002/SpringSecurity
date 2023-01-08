package com.cxx.domain;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * @author 陈喜喜
 * @date 2023-01-06 15:46
 */
@JsonInclude(JsonInclude.Include.NON_NULL)  //除去json数据中的空值
public class ResponseResult<T> {
    private Integer code;//状态码
    private String msg;//提示信息
    private T data;//结果数据

    @Override
    public String toString() {
        return "ResponseResult{" +
                "code=" + code +
                ", msg='" + msg + '\'' +
                ", data=" + data +
                '}';
    }

    public Integer getCode() {
        return code;
    }

    public void setCode(Integer code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public ResponseResult(Integer code, T data) {
        this.code = code;
        this.data = data;
    }

    public ResponseResult(Integer code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public ResponseResult() {
    }

    public ResponseResult(Integer code, String msg, T data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }
}
