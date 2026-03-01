package com.smart.mobility.smartmobilitygateway01.config;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtHeaderFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated)
                .cast(Authentication.class)
                .flatMap(authentication -> {
                    if (authentication instanceof JwtAuthenticationToken jwtToken) {
                        Jwt jwt = jwtToken.getToken();

                        // Extract Subject (User ID) from Keycloak Token
                        String userId = jwt.getSubject();

                        // Extract optional claims mapped in Keycloak
                        String email = jwt.getClaimAsString("email");
                        String tempName = jwt.getClaimAsString("name");
                        if (tempName == null) {
                            tempName = jwt.getClaimAsString("preferred_username");
                        }

                        final String finalEmail = email;
                        final String finalName = tempName;

                        // Mutate request to add headers for downstream microservices
                        ServerWebExchange mutatedExchange = exchange.mutate()
                                .request(r -> {
                                    r.header("X-User-Id", userId);
                                    if (finalEmail != null)
                                        r.header("X-User-Email", finalEmail);
                                    if (finalName != null)
                                        r.header("X-User-Name", finalName);

                                    // // Forward the Original Bearer Token Downstream
                                    // r.header("Authorization", "Bearer " + jwt.getTokenValue());
                                })
                                .build();

                        return chain.filter(mutatedExchange);
                    }
                    return chain.filter(exchange);
                })
                .switchIfEmpty(chain.filter(exchange)); // Proceed without headers if unauthenticated (e.g., /eureka)
    }

    @Override
    public int getOrder() {
        return -1; // Execute early in the filter chain
    }
}
