package com.smart.mobility.smartmobilitygateway01.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import reactor.core.publisher.Mono;

import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .cors(ServerHttpSecurity.CorsSpec::disable)
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(authenticationEntryPoint())
                        .accessDeniedHandler(accessDeniedHandler()))
                .authorizeExchange(exchanges -> exchanges
                        // Public endpoints
                        .pathMatchers("/eureka/**").permitAll()
                        .pathMatchers(HttpMethod.POST, "/users/register").permitAll()

                        // Admin endpoints
                        .pathMatchers("/admin/**").hasRole("ADMIN")

                        // User endpoints
                        .pathMatchers("/users/me").hasRole("USER")
                        .pathMatchers("/users/summary/me").hasRole("USER")
                        .pathMatchers("/api/passes/me/**").hasRole("USER")

                        // Inter-service endpoints (Require authentication with at least USER or ADMIN)
                        .pathMatchers("/users/**").hasAnyRole("USER", "ADMIN")
                        .pathMatchers("/api/passes/**").hasAnyRole("USER", "ADMIN")
                        .pathMatchers("/api/subscriptions/**").hasAnyRole("USER", "ADMIN")
                        .pathMatchers("/trips/**").hasAnyRole("USER", "ADMIN")
                        .pathMatchers("/api/pricing/**").hasAnyRole("USER", "ADMIN")
                        .pathMatchers("/api/payments/**").hasAnyRole("USER", "ADMIN")
                        .pathMatchers("/accounts/**").hasAnyRole("USER", "ADMIN")

                        // Fallback
                        .anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(grantedAuthoritiesExtractor())));

        return http.build();
    }

    @Bean
    public ServerAuthenticationEntryPoint authenticationEntryPoint() {
        return (exchange, e) -> {
            String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
            String tokenStatus = (authHeader != null) ? "Token present but invalid or expired" : "Token missing";

            logger.error("401 Unauthorized: Path: {} | Status: {} | Reason: {}",
                    exchange.getRequest().getPath(), tokenStatus, e.getMessage());

            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.UNAUTHORIZED);
            String body = String.format(
                    "{\"status\": 401, \"error\": \"Unauthorized\", \"message\": \"%s\", \"details\": \"%s\", \"path\": \"%s\"}",
                    e.getMessage(), tokenStatus, exchange.getRequest().getPath());
            return response.writeWith(Mono.just(response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8))));
        };
    }

    @Bean
    public ServerAccessDeniedHandler accessDeniedHandler() {
        return (exchange, e) -> ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .flatMap(auth -> {
                    String roles = auth.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.joining(", "));

                    logger.error("403 Forbidden: Path: {} | User: {} | Roles actual: {} | Reason: {}",
                            exchange.getRequest().getPath(), auth.getName(), roles, e.getMessage());

                    ServerHttpResponse response = exchange.getResponse();
                    response.setStatusCode(HttpStatus.FORBIDDEN);
                    String body = String.format(
                            "{\"status\": 403, \"error\": \"Forbidden\", \"message\": \"Access Denied\", \"details\": \"You have roles: [%s]\", \"path\": \"%s\"}",
                            roles, exchange.getRequest().getPath());
                    return response
                            .writeWith(Mono.just(response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8))));
                })
                .switchIfEmpty(Mono.defer(() -> {
                    logger.error("403 Forbidden (Unauthenticated): Path: {} | Reason: {}",
                            exchange.getRequest().getPath(), e.getMessage());
                    ServerHttpResponse response = exchange.getResponse();
                    response.setStatusCode(HttpStatus.FORBIDDEN);
                    String body = String.format("{\"status\": 403, \"error\": \"Forbidden\", \"message\": \"%s\"}",
                            e.getMessage());
                    return response
                            .writeWith(Mono.just(response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8))));
                }));
    }

    private Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }

    /**
     * Converter to extract nested Keycloak roles into Spring Security
     * GrantedAuthorities.
     * Looks at realm_access.roles in the JWT.
     */
    static class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
        @Override
        @SuppressWarnings("unchecked")
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");
            if (realmAccess == null || realmAccess.isEmpty()) {
                return Collections.emptyList();
            }

            Collection<String> roles = (Collection<String>) realmAccess.get("roles");
            if (roles == null || roles.isEmpty()) {
                return Collections.emptyList();
            }

            return roles.stream()
                    // Map Keycloak root roles to Spring Security format
                    // Default keycloak roles might lack the ROLE_ prefix but in realm-export.json
                    // we can see roles like "ROLE_USER" and "ROLE_ADMIN".
                    // So we add "ROLE_" if it's missing just for safety or leave as is if present.
                    .map(roleName -> {
                        if (roleName.startsWith("ROLE_")) {
                            return new SimpleGrantedAuthority(roleName);
                        } else {
                            return new SimpleGrantedAuthority("ROLE_" + roleName);
                        }
                    })
                    .collect(Collectors.toList());
        }
    }
}
