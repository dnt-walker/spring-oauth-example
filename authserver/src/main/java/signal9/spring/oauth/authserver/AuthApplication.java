package signal9.spring.oauth.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.io.IOException;
import java.security.KeyPair;

@EnableJpaAuditing
@SpringBootApplication
public class AuthApplication {
    public static void main(String[] args) throws IOException {
        SpringApplication.run(AuthApplication.class, args);
    }
}
