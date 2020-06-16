package signal9.spring.oauth.authserver.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import signal9.spring.oauth.authserver.entity.EndUser;

@Repository
public interface UserRepository extends JpaRepository<EndUser, Long> {
    @Query("select u from EndUser u where u.userName = :username")
    EndUser findByUsername(@Param("username") String username);
}