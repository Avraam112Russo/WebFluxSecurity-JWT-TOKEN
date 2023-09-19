package com.russozaripov.springsecurityreactivejwt.models;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class RequestLoginDTO {
    private String username;
    private String password;
}
