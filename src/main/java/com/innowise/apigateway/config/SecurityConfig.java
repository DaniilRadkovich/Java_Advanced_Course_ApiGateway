package com.innowise.apigateway.config;

import com.innowise.apigateway.security.JwtReactiveAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final JwtReactiveAuthenticationFilter jwtReactiveAuthenticationFilter;

  @Bean
  public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    return http
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
        .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)

        .authorizeExchange(exchanges -> exchanges
            .pathMatchers("/api/v1/auth/login").permitAll()
            .pathMatchers("/api/v1/auth/register").permitAll()
            .anyExchange().authenticated()
        )
        .addFilterBefore(jwtReactiveAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
        .build();
  }
}
