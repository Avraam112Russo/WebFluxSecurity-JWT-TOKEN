package com.russozaripov.springsecurityreactivejwt.models.RequestResponse;

public interface ResponseRequest<T>  {
    T getData();
    String getMessage();
}
