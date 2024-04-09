package vn.botstore.code.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class AuthenticateResponse {
    private String username;
    private List<String> roles;
}
