package vn.botstore.code.user.entity;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import vn.botstore.code.user.repo.RoleRepository;

@Component
@RequiredArgsConstructor
public class ModelUtils implements CommandLineRunner {
    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        // Check if the Role table is empty
        if (roleRepository.count() == 0) {
            // Generate three records and save them to the Role table
            Role role1 = new Role(ERole.ROLE_ADMIN);
            Role role2 = new Role(ERole.ROLE_MODERATOR);
            Role role3 = new Role(ERole.ROLE_USER);
            roleRepository.save(role1);
            roleRepository.save(role2);
            roleRepository.save(role3);
        }
    }
}
