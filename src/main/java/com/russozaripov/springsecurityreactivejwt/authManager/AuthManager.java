package com.russozaripov.springsecurityreactivejwt.authManager;

import com.russozaripov.springsecurityreactivejwt.bearerToken.TokenBearer;
import com.russozaripov.springsecurityreactivejwt.service.ServiceJWT;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Collection;
@Component
public class AuthManager implements ReactiveAuthenticationManager {
    private final ServiceJWT serviceJWT;
    private final ReactiveUserDetailsService userDetailsService;

    public AuthManager(ServiceJWT serviceJWT, ReactiveUserDetailsService userDetailsService) {
        this.serviceJWT = serviceJWT;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono
                .justOrEmpty(
                        authentication
                )
                .cast(TokenBearer.class)
                .flatMap((tokenBearer) -> {
                    String username = serviceJWT.getUserName(tokenBearer.getCredentials());
                    Mono<UserDetails> foundUser = userDetailsService.findByUsername(username).defaultIfEmpty(new UserDetails() {
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
                    });
                    Mono<Authentication> userAuthentication = foundUser.flatMap((userDetails) -> {
                        if (userDetails.getUsername() == null){
                             Mono.error(new IllegalArgumentException("Invalid token"));
                        }
                        if (serviceJWT.validateToken(userDetails, tokenBearer.getCredentials())){
                            return Mono.justOrEmpty(new UsernamePasswordAuthenticationToken(
                                    userDetails.getUsername(),
                                    userDetails.getPassword(),
                                    userDetails.getAuthorities()
                            ));
                        }
                        Mono.error(new IllegalArgumentException("Токен не валиден/истек срок годсности"));

                        return Mono.justOrEmpty(new UsernamePasswordAuthenticationToken(
                                userDetails.getUsername(),
                                userDetails.getPassword(),
                                userDetails.getAuthorities()
                        ));
                    });
                    return userAuthentication;
                });

    }
}
