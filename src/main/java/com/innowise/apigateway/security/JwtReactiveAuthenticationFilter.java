package com.innowise.apigateway.security;

import com.innowise.apigateway.exception.TokenLifetimeValidationException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Collection;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtReactiveAuthenticationFilter implements WebFilter {

  private final JwtService jwtService;
  private final ObjectMapper objectMapper;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, @NonNull WebFilterChain chain) {
    ServerHttpRequest request = exchange.getRequest();

    log.info("METHOD = {}", request.getMethod());
    log.info("URI = {}", request.getURI().getPath());
    log.info("CONTENT-TYPE = {}", request.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE));

    String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return chain.filter(exchange);
    }

    try {
      String jwt = authHeader.substring(7);
      Claims claims = jwtService.parse(jwt);
      String username = claims.getSubject();

      if (username == null || username.isBlank()) {
        throw new JwtException("Username must not be empty!");
      }

      String tokenType = claims.get("type", String.class);
      if (tokenType == null || !tokenType.equals("access")) {
        throw new JwtException("Wrong token type used for authentication!");
      }

      String role = claims.get("role", String.class);

      if (!Set.of("USER", "ADMIN").contains(role)) {
        throw new JwtException("Invalid role! Please provide a valid role.");
      }

      UUID userId = UUID.fromString(claims.get("id", String.class));

      Collection<SimpleGrantedAuthority> authorities = List.of(
          new SimpleGrantedAuthority("ROLE_" + role));

      Authentication authentication = new UsernamePasswordAuthenticationToken(userId, null,
          authorities);

      ServerHttpRequest mutatedRequest = request.mutate()
          .header("X-User-Id", userId.toString())
          .header("X-User-Role", role)
          .build();

      ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

      return chain.filter(mutatedExchange)
          .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));

    } catch (TokenLifetimeValidationException e) {
      return sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Unauthorized!",
          "The token has expired! Required token refresh!");
    } catch (JwtException e) {
      return sendErrorResponse(exchange, HttpStatus.UNAUTHORIZED, "Unauthorized!",
          "Invalid token data! Please provide a valid token.");
    } catch (Exception e) {
      return sendErrorResponse(exchange, HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error!",
          "Something went wrong!");
    }
  }

  private Mono<Void> sendErrorResponse(ServerWebExchange exchange, HttpStatus status, String error,
      String message) {
    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(status);
    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

    Map<String, Object> body = new HashMap<>();
    body.put("timestamp", LocalDateTime.now().toString());
    body.put("path", exchange.getRequest().getURI().getPath());
    body.put("status", status.value());
    body.put("error", error);
    body.put("message", message);

    try {
      byte[] bytes = objectMapper.writeValueAsBytes(body);
      DataBuffer buffer = response.bufferFactory().wrap(bytes);
      return response.writeWith(Mono.just(buffer));
    } catch (JsonProcessingException e) {
      log.error("Some problems with error writing JSON error response...", e);
      return response.setComplete();
    }
  }
}
