package signal9.spring.oauth.authserver.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import javax.persistence.*;
import java.util.Date;

@Slf4j
@Entity
@Getter
@Table(name = "end_user")
@NoArgsConstructor
public class EndUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 20, nullable = false, unique = true)
    private String userName;

    @Column(length = 100, nullable = false)
    private String password;

    //1:수퍼관리자, 2:관리자, 3:사용자
    @Column(length = 1, nullable = false)
    private String userType;

    @Column(nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date regDate = new Date();
}
