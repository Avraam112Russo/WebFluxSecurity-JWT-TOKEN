package com.russozaripov.springsecurityreactivejwt.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class ServiceJWT {
    private final SecretKey secretKey;
    private final JwtParser jwtParser;

    public ServiceJWT() {
        this.secretKey = Keys.hmacShaKeyFor("123456789dmksdmskdskdmskmdskmdsddsssssssssssssssssdd".getBytes()); // создаем шифрованный ключ на основе секретного ключа в данном случае 1-9
        this.jwtParser = Jwts.parserBuilder().setSigningKey(this.secretKey).build(); // объект который парсит токен
    }
    public String generateToken(String username){ // генерируем токен на основе username
        JwtBuilder jwtBuilder = Jwts.builder()
                .setSubject(username) // payload
                .setIssuedAt(Date.from(Instant.now()))// токен начинает действовать с момента запуска данного метода
                .setExpiration(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
                .signWith(secretKey);
        return jwtBuilder.compact();
    }
    public String getUserName(String token){
       Claims claims = jwtParser.parseClaimsJws(token).getBody(); // получили payload
        return claims.getSubject();
    }

    public boolean validateToken(UserDetails userDetails, String token){
        Claims claims = jwtParser.parseClaimsJws(token).getBody();
        boolean unexpiredToken = claims.getExpiration().after(Date.from(Instant.now())); // проверяем срок годности токена, сравниваем его время жизни и текущий момент времени когда вызывался метод
        return unexpiredToken && claims.getSubject() == userDetails.getUsername(); // метод вернет тру, если имя юзера и имя в токене совпадает, а так же не истек срок годности токена
    }
}
