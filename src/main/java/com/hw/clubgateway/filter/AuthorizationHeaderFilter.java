package com.hw.clubgateway.filter;

import com.hw.clubgateway.token.TokenManager;
import com.hw.clubgateway.token.TokenType;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private Environment env;
    private TokenManager tokenManager;

    public AuthorizationHeaderFilter(Environment env, TokenManager tokenManager) {
        super(Config.class);
        this.env = env;
        this.tokenManager = tokenManager;
    }

    // API 호출 시 헤더에 로그인 시 받은 토큰을 전달해주는 작업 진행
    // 토큰 존재 ? 적절한 인증 ? 토큰 제대로 발급 ?, ...
    @Override
    public GatewayFilter apply(Config config) {
        return (((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // 헤더에 존재하는 검증
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
            }

            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            String jwt = authorizationHeader.replace("Bearer ", "");

            // jwt 검증
//            if (!isJwtValid(jwt)) {
//                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
//            }

            return chain.filter(exchange);

        }));
    }

    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;

        // JWT subject 를 추출하여 검증

        try {
            Claims tokenClaims = tokenManager.getTokenClaims(jwt);
            if (!TokenType.ACCESS.name().equals(tokenClaims.getSubject())) {
                throw new Exception();
            }

            // 액세스 토큰 만료 시간 검증
            if (tokenManager.isTokenExpired(tokenClaims.getExpiration())) {
                throw new Exception();
            }
//            subject = Jwts.parser().setSigningKey(env.getProperty("token.secret"))
//                    .parseClaimsJws(jwt).getBody()
//                    .getSubject();
        } catch (Exception e) { // 파싱 중 오류 처리
            returnValue = false;
        }

//        if (subject == null || subject.isEmpty()) {
//            returnValue = false;
//        }

        return returnValue;

    }

    // 에러 메시지 반환
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(err);
        return response.setComplete();
    }

    public static class Config {

    }
}
