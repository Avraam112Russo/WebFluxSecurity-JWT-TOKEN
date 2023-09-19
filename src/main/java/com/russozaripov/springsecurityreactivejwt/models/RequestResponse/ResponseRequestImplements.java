package com.russozaripov.springsecurityreactivejwt.models.RequestResponse;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
public class ResponseRequestImplements<T> implements ResponseRequest<T>{
    private T data;
    private String message;
    @Override
    public T getData() {
       return this.data;
    }

    @Override
    public String getMessage() {
        return this.message;
    }
}
