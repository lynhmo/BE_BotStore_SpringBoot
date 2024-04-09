package vn.botstore.code.user.advice;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import vn.botstore.code.user.dto.response.MessageResponse;

@ControllerAdvice
public class ResExceptionHandler{
    @ExceptionHandler(MethodArgumentNotValidException.class)
    protected ResponseEntity<?> handleConflict(RuntimeException ex, WebRequest request) {
        String bodyOfResponse = "Invalid input!";
        return ResponseEntity.badRequest().body(new MessageResponse(bodyOfResponse + "\n Exception: " + ex));
    }
}