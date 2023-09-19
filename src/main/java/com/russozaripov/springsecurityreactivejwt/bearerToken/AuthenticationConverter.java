package com.russozaripov.springsecurityreactivejwt.bearerToken;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

// convert header value into Authentication token "Bearer " token
@Component
public class AuthenticationConverter implements ServerAuthenticationConverter {
    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return Mono.justOrEmpty(
                exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION) // получили значение из заголовка
        ).filter(allHeader -> allHeader.startsWith("Bearer ")) // проверяем начинается с Bearer или нет
                .map(token -> token.substring(7)) // достаем только сам токен
                .map(token -> new TokenBearer(token)); // создаем наш кастомный объект который имплементирует Authentication
    }
}
