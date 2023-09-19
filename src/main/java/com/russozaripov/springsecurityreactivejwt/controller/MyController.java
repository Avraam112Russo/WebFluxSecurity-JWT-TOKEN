package com.russozaripov.springsecurityreactivejwt.controller;

import com.russozaripov.springsecurityreactivejwt.models.RequestLoginDTO;
import com.russozaripov.springsecurityreactivejwt.models.RequestResponse.ResponseRequest;
import com.russozaripov.springsecurityreactivejwt.models.RequestResponse.ResponseRequestImplements;
import com.russozaripov.springsecurityreactivejwt.service.ServiceJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Collection;

@RestController
@RequestMapping("/api/v1")
public class MyController {

    @Autowired
    private MapReactiveUserDetailsService mapReactiveUserDetailsService;
    @Autowired
    private ServiceJWT serviceJWT;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public Mono<ResponseEntity<ResponseRequest<String>>> auth(@RequestBody RequestLoginDTO loginDTO){

        Mono<UserDetails> foundUser = mapReactiveUserDetailsService.findByUsername(loginDTO.getUsername()).defaultIfEmpty(new UserDetails() {
            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return null;
            }

            @Override
            public String getPassword() {
                return null;
            }

            @Override
            public String getUsername() {
                return null;
            }

            @Override
            public boolean isAccountNonExpired() {
                return false;
            }

            @Override
            public boolean isAccountNonLocked() {
                return false;
            }

            @Override
            public boolean isCredentialsNonExpired() {
                return false;
            }

            @Override
            public boolean isEnabled() {
                return false;
            }
        }); // mapReactiveUserDetailsService ищет пользователя по тем данным что ввели на клиенте
        return foundUser.flatMap(userDetails -> {
            if (userDetails.getUsername() == null){
                return Mono.just(ResponseEntity.status(404).body(new ResponseRequestImplements("Status 404", "User not found")));
            }
            if (passwordEncoder.matches(loginDTO.getPassword(), userDetails.getPassword())){
                return Mono.just(ResponseEntity.ok(new ResponseRequestImplements<>(serviceJWT.generateToken(userDetails.getUsername()), "success.")));
            }
            return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ResponseRequestImplements("error", "Неверный пароль")));
        });

//
//        return foundUser.flatMap(userDetails -> {
//            // проверяем корректность пароля
//            if (userDetails != null){
//                if (passwordEncoder.matches(loginDTO.getPassword(), userDetails.getPassword()) && userDetails.getUsername().equals(loginDTO.getUsername())){
//                    return Mono.just(
//                            ResponseEntity.ok(
//                                    new ResponseRequestImplements<>(
//                                            // генерируем токен и передаем в наш DTO
//                                            serviceJWT.generateToken(userDetails.getUsername()), "success."
//                                    )
//                            )
//                    );
//                }else {
//                    return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
//                            new ResponseRequestImplements<>("", "Неверный password или username"))
//                    );
//                }
//            }
//            return Mono.just(ResponseEntity
//                    .status(HttpStatus.UNAUTHORIZED)
//                    .body(new ResponseRequestImplements<>("", "Пользователь с такими данными не найден")));
//        });
    }

    @GetMapping("/test")
    public Mono<ResponseEntity<ResponseRequest<String>>> test(){
        return Mono.just(
                ResponseEntity.ok(
                        new ResponseRequestImplements<>("Welcome to the private club", "message")
                )
        );
    }
}
