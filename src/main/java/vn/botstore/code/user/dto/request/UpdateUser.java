package vn.botstore.code.user.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import vn.botstore.code.user.entity.Role;

import java.util.HashSet;
import java.util.Set;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UpdateUser {
    private Long id;
    @Size(max = 50)
    private String fullName;

//    @Column(name = "updated_at", nullable = false)
//    @LastModifiedDate
//    private Instant updatedAt;

    private Set<Role> role;

    @Size(max = 10)
    private String phone;

    @Size(max = 100)
    private String address;

    private String avatar;
}
