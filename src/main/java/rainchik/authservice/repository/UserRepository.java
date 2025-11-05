package rainchik.authservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import rainchik.authservice.data.UserDetailsImpl;

import java.util.Optional;
// в будущем планируется перейти из локального хранилища на postgreSQL
@Repository
public interface UserRepository extends JpaRepository<UserDetailsImpl, Long> {
    Optional<UserDetailsImpl> findByUsername(String username);

    Optional<UserDetailsImpl> findByEmail(String email);
}
