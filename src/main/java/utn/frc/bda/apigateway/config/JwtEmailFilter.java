package utn.frc.bda.apigateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Configuration
public class JwtEmailFilter {

    @Value("${app.jwt.secret}")
    private String secretKey;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public GlobalFilter extractEmailFromJwt() {
        return (exchange, chain) -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                try {
                    Claims claims = Jwts.parser()
                            .setSigningKey(secretKey.getBytes())
                            .parseClaimsJws(token)
                            .getBody();

                    String email = claims.getSubject(); // el "sub" del token

                    // Agregamos el email como header para los microservicios internos
                    ServerWebExchange mutated = exchange.mutate()
                            .request(r -> r.headers(h -> h.add("X-User-Email", email)))
                            .build();

                    return chain.filter(mutated);
                } catch (Exception e) {
                    System.out.println("❌ Error parsing JWT: " + e.getMessage());
                }
            }
            return chain.filter(exchange);
        };
    }
}
