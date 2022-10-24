package com.hw.clubgateway.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenManager {


    @Value("${token.access-token-expiration-time}")
    private String accessTokenExpirationTime;

    @Value("${token.refresh-token-expiration-time}")
    private String refreshTokenExpirationTime;

    @Value("${token.secret}")
    private String tokenSecret;

    public String getUserEmail(String accessToken) {
        String email;
        try {
            Claims claims = Jwts.parser().setSigningKey(tokenSecret)
                    .parseClaimsJws(accessToken).getBody();
            email = claims.getAudience();
        } catch (Exception e){
            e.printStackTrace();
            // TODO 에러추가
            throw new RuntimeException(e);
//            throw new NotValidTokenException(ErrorCode.NOT_VALID_TOKEN);
        }
        return email;
    }

    public boolean validateToken(String token){
        try {
            Jwts.parser().setSigningKey(tokenSecret)
                    .parseClaimsJws(token);
            return true;
        } catch(JwtException e) {  //토큰 변조
            log.info("잘못된 jwt token", e);
        } catch (Exception e){
            log.info("jwt token 검증 중 에러 발생", e);
        }
        return false;
    }

    public Claims getTokenClaims(String token) {
        Claims claims;
        try {
            claims = Jwts.parser().setSigningKey(tokenSecret)
                    .parseClaimsJws(token).getBody()
            ;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
//            throw new NotValidTokenException(ErrorCode.NOT_VALID_TOKEN);
        }
        return claims;
    }

    public String getTokenType(String token) {
        String tokenType;
        try {
            Claims claims = Jwts.parser().setSigningKey(tokenSecret)
                    .parseClaimsJws(token).getBody();
            tokenType = claims.getSubject();
        }catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
//            throw new NotValidTokenException(ErrorCode.NOT_VALID_TOKEN);
        }

        return tokenType;
    }

    public boolean isTokenExpired(Date tokenExpiredTime) {
        Date now = new Date();
        if(now.after(tokenExpiredTime)) {
            return true;
        }
        return false;
    }

    public String getRole(String token) {

        String role;
        try {
            Claims claims = Jwts.parser().setSigningKey(tokenSecret)
                    .parseClaimsJws(token).getBody();

            role = (String) claims.get("role");
        }catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
//            throw new NotValidTokenException(ErrorCode.NOT_VALID_TOKEN);
        }

        return role;
    }
}
