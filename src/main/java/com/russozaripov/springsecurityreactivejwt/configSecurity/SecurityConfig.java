package com.russozaripov.springsecurityreactivejwt.configSecurity;

import com.russozaripov.springsecurityreactivejwt.authManager.AuthManager;
import com.russozaripov.springsecurityreactivejwt.bearerToken.AuthenticationConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public MapReactiveUserDetailsService detailsService(BCryptPasswordEncoder passwordEncoder){

        UserDetails user = User.builder()
                .username("USER")
                .password(passwordEncoder.encode("12345"))
                .roles("USER")
                .build();
        return new MapReactiveUserDetailsService(user);
    }
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http, AuthenticationConverter jwtConverter, AuthManager jwtManager){
        AuthenticationWebFilter webFilter = new AuthenticationWebFilter(jwtManager);
        webFilter.setServerAuthenticationConverter(jwtConverter);
        return http
                .authorizeExchange( auth -> {
                    auth.pathMatchers("/api/v1/login").permitAll()
                            .pathMatchers("/api/v1/test").authenticated();
                })
                .addFilterAt(webFilter, SecurityWebFiltersOrder.AUTHORIZATION)
                .csrf().disable()
                .cors().disable()
                .httpBasic().disable()
                .formLogin().disable().build();
    }

}
