package com.innowise.apigateway.exception.handler;

import com.innowise.apigateway.exception.ErrorResponse;
import io.jsonwebtoken.JwtException;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<Map<String, Object>> handleMethodArgumentNotValidException(
      MethodArgumentNotValidException ex) {

    HttpStatus status = HttpStatus.BAD_REQUEST;

    Map<String, Object> errorResponse = Map.of(
            "Error response",
            "Validation entered arguments failed!",
            "Info",
            ex.getBindingResult().getFieldErrors().stream()
                .map(err -> err.getField() + ": " + err.getDefaultMessage())
                .collect(Collectors.joining(", ")));

    return ResponseEntity.status(status).body(errorResponse);
  }

  @ExceptionHandler(MethodArgumentTypeMismatchException.class)
  public ResponseEntity<String> handleMethodArgumentTypeMismatchException(
      MethodArgumentTypeMismatchException ex) {
    HttpStatus status = HttpStatus.BAD_REQUEST;

    String typeName = Optional.ofNullable(ex.getRequiredType()).map(Class::getSimpleName)
        .orElse("Unknown");

    String message = String.format("Parameter '%s' should be of type %s!", ex.getName(), typeName);

    return ResponseEntity.status(status).body(message);
  }

  @ExceptionHandler(AuthorizationDeniedException.class)
  public ResponseEntity<ErrorResponse> handleAuthorizationDeniedException(
      AuthorizationDeniedException ex, ServerHttpRequest request) {

    HttpStatus status = HttpStatus.FORBIDDEN;

    ErrorResponse errorResponse = new ErrorResponse(
            LocalDateTime.now(),
            status.value(),
            status.getReasonPhrase(),
            ex.getMessage(),
            request.getURI().getPath(),
        ex.getClass().getSimpleName());

    return ResponseEntity.status(status).body(errorResponse);
  }

  @ExceptionHandler(JwtException.class)
  public ResponseEntity<ErrorResponse> handleJwtExceptionException(
      JwtException ex, ServerHttpRequest request) {

    HttpStatus status = HttpStatus.BAD_REQUEST;

    ErrorResponse errorResponse = new ErrorResponse(
        LocalDateTime.now(),
        status.value(),
        status.getReasonPhrase(),
        ex.getMessage(),
        request.getURI().getPath(),
        ex.getClass().getSimpleName());

    return ResponseEntity.status(status).body(errorResponse);
  }
}
