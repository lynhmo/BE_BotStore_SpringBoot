package vn.botstore.code.user.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import vn.botstore.code.user.entity.ERole;
import vn.botstore.code.user.entity.Role;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(ERole name);
}