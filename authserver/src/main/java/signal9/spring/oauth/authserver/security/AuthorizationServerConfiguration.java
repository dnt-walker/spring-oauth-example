package signal9.spring.oauth.authserver.security;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.password.*;
import org.springframework.security.oauth2.config.annotation.builders.JdbcClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.*;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.sql.DataSource;

/**
 * An instance of Legacy Authorization Server (spring-security-oauth2) that uses a single,
 * not-rotating key and exposes a JWK endpoint.
 *
 * See
 * <a
 * 	target="_blank"
 * 	href="https://docs.spring.io/spring-security-oauth2-boot/docs/current-SNAPSHOT/reference/htmlsingle/">
 * 	Spring Security OAuth Autoconfig's documentation</a> for additional detail
 *
 * @author Josh Cummings
 * @since 5.1
 */
@Slf4j
@EnableAuthorizationServer
@Configuration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    AuthenticationManager authenticationManager;
//    KeyPair keyPair;



    @Autowired
    @Qualifier("dataSource")
    private DataSource dataSource;

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    @Qualifier("passwordEncoder")
    private PasswordEncoder passwordEncoder;

    public AuthorizationServerConfiguration(
            AuthenticationConfiguration authenticationConfiguration) //, KeyPair keyPair)
        throws Exception {

        this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
//        this.keyPair = keyPair;
    }

    /**
     * OAuth 서버에 접속하는 클라이언트 정의.
     * client_id, client_secret 등을 저장하는 클라이언트 저장소에 대한 모든 CRUD는 ClientDetailsService 인터페이스로 구현
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.withClientDetails(jdbcClientService());

    }

    /**
     * TokenStore, ApprovalStore, AuthenticationManager 셋팅.
     * TokenStore 인터페이스는 Access Token, Refresh Token과 관련된 인증 데이터를 저장, 검색, 제거, 읽기에 대한 정의
     * ApprovalStore 인터페이스는 리소스의 소유자의 승인을 추가, 검색, 취소 하기위한 메서드들이 정의
     * @param endpoints
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(this.authenticationManager)
                .tokenStore(tokenStore())
                .approvalStore(approvalStore())
                .accessTokenConverter(accessTokenConverter());
    }

    @Bean
    @Primary
    public DefaultTokenServices tokenService() {
        log.info("## load tokenService.");
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }

    /**
     * OAuth2 인정서버 자체의 보안정보 설정하는 부분
     * 패스워드 엔코더 설정
     * 패스워드 인코딩해서 관리 하겠다
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.passwordEncoder(passwordEncoder)
        // 다른 어플리케이션에서 인증서버 붙을때 accessToken이 유효한지 확인할수 있도록 허용. 기본은 denyAll
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("denyAll()");
    }

    /**
     * Spring Security OAuth에서 access_token, refresh_token을 저장하는 토큰 저장소에 대한 모든 CRUD는 TokenStore 인터페이스로 구현
     * InMemoryTokenStore, JdbcTokenStore, RedisTokenStore 클래스가 제공
     *  JwtTokenStore는 생성된 토큰 정보가 내부에 암호화되어 있기때문에 토큰의 정보를 별도로 저장할 필요가 없다. 복화하면 원하는 정보가 있다.
     * configure(AuthorizationServerEndpointsConfigurer endpoints) 에서 endpoints.tokenStore() 변경.
     * @return
     */
    @Bean
    public TokenStore tokenStore() {
        // @formatter:off
        return new JwtTokenStore(accessTokenConverter());
        // @formatter:on
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        ClassPathResource classPathResource = new ClassPathResource("server.jks");
        if(classPathResource.exists() == false){
            log.error("Invalid filePath : {}", classPathResource.getPath().toString());
            throw new IllegalArgumentException();
        }

        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        KeyPair keyPair = new KeyStoreKeyFactory(classPathResource, "dfe18vd213cx".toCharArray())
                .getKeyPair("server_private", "dfe18vd213cx".toCharArray());
        converter.setKeyPair(keyPair);

        DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
        accessTokenConverter.setUserTokenConverter(new SubjectAttributeUserTokenConverter());
        converter.setAccessTokenConverter(accessTokenConverter);

        return converter;
    }

    @Bean
    public ClientDetailsService jdbcClientService() throws Exception {
        JdbcClientDetailsServiceBuilder clientDetailsServiceBuilder = new JdbcClientDetailsServiceBuilder();
        // PasswordEncoder는 직접안해도 Bean으로 등록하면 자동으로 적용된다. 기본이 {encoder type}xxx 형태의 비밀번호를 인/디코등한다.
        clientDetailsServiceBuilder.dataSource(dataSource);
        return clientDetailsServiceBuilder.build();
    }

//    @Bean
//    public TokenStore tokenStore() {
//        return new RedisTokenStore(jedisConnectionFactory());
//    }
//
//    @Bean
//    public JedisConnectionFactory jedisConnectionFactory() {
//        JedisConnectionFactory factory = new JedisConnectionFactory();
//        factory.setHostName("localhost");
//        factory.setPort(6379);
//        factory.setPassword("");
//        factory.setDatabase(1);
//        factory.setUsePool(true); return factory;
//    }

    @Bean
    public UserApprovalHandler userApprovalHandler() {
        ApprovalStoreUserApprovalHandler userApprovalHandler = new ApprovalStoreUserApprovalHandler();
        userApprovalHandler.setApprovalStore(approvalStore());
        userApprovalHandler.setClientDetailsService(this.clientDetailsService);
        userApprovalHandler.setRequestFactory(new DefaultOAuth2RequestFactory(this.clientDetailsService));
        return userApprovalHandler;
    }

    @Bean
    public ApprovalStore approvalStore() {
        return new JdbcApprovalStore(dataSource);
    }

}

/**
 * Legacy Authorization Server (spring-security-oauth2) does not support any
 * Token Introspection endpoint.
 *
 * This class adds ad-hoc support in order to better support the other samples in the repo.
 */
//@FrameworkEndpoint
//class IntrospectEndpoint {
//    TokenStore tokenStore;
//
//    IntrospectEndpoint(TokenStore tokenStore) {
//        this.tokenStore = tokenStore;
//    }
//
//    @PostMapping("/introspect")
//    @ResponseBody
//    public Map<String, Object> introspect(@RequestParam("token") String token) {
//        OAuth2AccessToken accessToken = this.tokenStore.readAccessToken(token);
//        Map<String, Object> attributes = new HashMap<>();
//        if (accessToken == null || accessToken.isExpired()) {
//            attributes.put("active", false);
//            return attributes;
//        }
//
//        OAuth2Authentication authentication = this.tokenStore.readAuthentication(token);
//
//        attributes.put("active", true);
//        attributes.put("exp", accessToken.getExpiration().getTime());
//        attributes.put("scope", accessToken.getScope().stream().collect(Collectors.joining(" ")));
//        attributes.put("sub", authentication.getName());
//
//        return attributes;
//    }
//}


///**
// * Legacy Authorization Server (spring-security-oauth2) does not support any
// * <a href target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">JWK Set</a> endpoint.
// *
// * This class adds ad-hoc support in order to better support the other samples in the repo.
// */
//@FrameworkEndpoint
//class JwkSetEndpoint {
//    KeyPair keyPair;
//
//    JwkSetEndpoint(KeyPair keyPair) {
//        this.keyPair = keyPair;
//    }
//
//    @GetMapping("/.well-known/jwks.json")
//    @ResponseBody
//    public Map<String, Object> getKey() {
//        RSAPublicKey publicKey = (RSAPublicKey) this.keyPair.getPublic();
//        RSAKey key = new RSAKey.Builder(publicKey).build();
//        return new JWKSet(key).toJSONObject();
//    }
//}

/**
 * An Authorization Server will more typically have a key rotation strategy, and the keys will not
 * be hard-coded into the application code.
 *
 * For simplicity, though, this sample doesn't demonstrate key rotation.
 */
//@Configuration
//class KeyConfig {
//    @Bean
//    KeyPair keyPair() {
//        try {
//            String privateExponent = "3851612021791312596791631935569878540203393691253311342052463788814433805390794604753109719790052408607029530149004451377846406736413270923596916756321977922303381344613407820854322190592787335193581632323728135479679928871596911841005827348430783250026013354350760878678723915119966019947072651782000702927096735228356171563532131162414366310012554312756036441054404004920678199077822575051043273088621405687950081861819700809912238863867947415641838115425624808671834312114785499017269379478439158796130804789241476050832773822038351367878951389438751088021113551495469440016698505614123035099067172660197922333993";
//            String modulus = "18044398961479537755088511127417480155072543594514852056908450877656126120801808993616738273349107491806340290040410660515399239279742407357192875363433659810851147557504389760192273458065587503508596714389889971758652047927503525007076910925306186421971180013159326306810174367375596043267660331677530921991343349336096643043840224352451615452251387611820750171352353189973315443889352557807329336576421211370350554195530374360110583327093711721857129170040527236951522127488980970085401773781530555922385755722534685479501240842392531455355164896023070459024737908929308707435474197069199421373363801477026083786683";
//            String exponent = "65537";
//
//            RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(exponent));
//            RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privateExponent));
//            KeyFactory factory = KeyFactory.getInstance("RSA");
//            return new KeyPair(factory.generatePublic(publicSpec), factory.generatePrivate(privateSpec));
//        } catch ( Exception e ) {
//            throw new IllegalArgumentException(e);
//        }

//        KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource("server.jks"), "dfe18v!d213cx".toCharArray())
//                .getKeyPair("auth", "dfe18v!d213cx".toCharArray());
//        return keyPair;
//    }
//}

/**
 * Legacy Authorization Server does not support a custom name for the user parameter, so we'll need
 * to extend the default. By default, it uses the attribute {@code user_name}, though it would be
 * better to adhere to the {@code sub} property defined in the
 * <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JWT Specification</a>.
 */
class SubjectAttributeUserTokenConverter extends DefaultUserAuthenticationConverter {
    @Override
    public Map<String, ?> convertUserAuthentication(Authentication authentication) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("sub", authentication.getName());
        if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
            response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
        }
        return response;
    }
}

// @formatter:off
//        String password = passwordEncoder.encode("secret");
//        log.info("## pass:" + password );
//        clients.inMemory()
//                .withClient("reader")
//                .authorizedGrantTypes("password")
//                .secret("{bcrypt}secret")
//                .scopes("read")
//                .accessTokenValiditySeconds(600_000_000);
//                .and()
//                .withClient("writer")
//                .authorizedGrantTypes("password")
//                .secret("{noop}secret")
//                .scopes("message:write")
//                .accessTokenValiditySeconds(600_000_000)
//                .and()
//                .withClient("noscopes")
//                .authorizedGrantTypes("password")
//                .secret("{noop}secret")
//                .scopes("none")
//                .accessTokenValiditySeconds(600_000_000);
// @formatter:on