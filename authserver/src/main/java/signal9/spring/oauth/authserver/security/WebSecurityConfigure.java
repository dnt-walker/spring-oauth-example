package signal9.spring.oauth.authserver.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure extends WebSecurityConfigurerAdapter {
    /**
     * 클라이언트와 토큰 관리는 Spring Security OAuth 모듈이 담당하지만 사용자 관리는 Spring Security의 몫이다.
     * /oauth/authorize 요청을 처리하려면 사용자 저장소에 접근할 수 있어야 한
     */
    @Override
    protected void configure(HttpSecurity security) throws Exception {
        security.csrf().disable()
                .headers().frameOptions().disable()
                .and()
                .authorizeRequests()
                .antMatchers("/oauth/authorize").permitAll()
                .antMatchers("/oauth/**", "/oauth2/callback").permitAll()
				.antMatchers("/.well-known/jwks.json").permitAll()
                .and()
                .formLogin().and()
                .httpBasic();
    }

	/**
	 * 인증 프로세스를 사용자 정의하려면 AuthenticationProvider를 직접 구현해야함.
	 * 단순 몇가지 항목만 셋팅가능.

	 * @return
	 */
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("subject")
//                .password("password")
//                .roles("USER");
//    }
	/**
	 * UserDetailsService는 사용자 계정과 관련된 데이터를로드하기위한 DAO 인터페이스.
	 * DaoAuthenticationProvider는 UserDetailsService를 사용하여 제출된 값과 비교하기 위해 사용자의 비밀번호 (및 기타 데이터) 로딩하는데 사용.
	 * 인증 프로세스를 사용자 정의하려면 AuthenticationProvider를 직접 구현.
	 */
	@Bean
	@Override
	public UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withDefaultPasswordEncoder()
					.username("subject")
					.password("password")
					.roles("USER")
					.build());
	}

	/**
	 * {id}xxxx 형식의 비밀번호를 인식시킬려면 딜리게이트로 PasswordEncoder 을 지정해야한다.
	 * @return
	 */
	@Bean
	public static PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
}
