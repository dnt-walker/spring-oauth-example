package signal9.spring.oauth.authserver.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class CommonBean {
    /**
     * {id}xxxx 형식의 비밀번호를 인식시킬려면 딜리게이트로 PasswordEncoder 을 지정해야한다.
     * @return
     */
    @Bean
    public static PasswordEncoder passwordEncoder() {
        // @formatter:off
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        // @formatter:on
    }
}
