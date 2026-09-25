package org.romainlavabre.security.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * Routing by issuer, key checking and audience, against tokens really signed. Kratos is given its public
 * keys statically, Hydra publishes them on a jwks endpoint, served here by a local HTTP server.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class SecurityTest {
    private static final String KRATOS_ISSUER = "http://kratos:4433/";
    private static final String HYDRA_ISSUER  = "http://hydra:4444/";
    private static final String AUDIENCE      = "marea";

    private static RSAKey kratosKey;
    private static RSAKey hydraKey;
    private static RSAKey foreignKey;

    private Security   security;
    private HttpServer hydraJwksServer;


    @BeforeClass
    public static void generateKeys() throws JOSEException {
        kratosKey  = new RSAKeyGenerator( 2048 ).keyID( "kratos" ).algorithm( JWSAlgorithm.RS256 ).generate();
        hydraKey   = new RSAKeyGenerator( 2048 ).keyID( "hydra" ).generate();
        foreignKey = new RSAKeyGenerator( 2048 ).keyID( "kratos" ).algorithm( JWSAlgorithm.RS256 ).generate();
    }


    @Before
    public void setUp() throws Exception {
        security = new Security( null );

        hydraJwksServer = HttpServer.create( new InetSocketAddress( "127.0.0.1", 0 ), 0 );
        hydraJwksServer.createContext( "/.well-known/jwks.json", exchange -> {
            byte[] body = new JWKSet( hydraKey.toPublicJWK() ).toString().getBytes( StandardCharsets.UTF_8 );

            exchange.getResponseHeaders().add( "Content-Type", "application/json" );
            exchange.sendResponseHeaders( 200, body.length );

            try ( OutputStream outputStream = exchange.getResponseBody() ) {
                outputStream.write( body );
            }
        } );
        hydraJwksServer.start();

        configure( AUDIENCE );
    }


    @After
    public void tearDown() {
        hydraJwksServer.stop( 0 );
    }


    @Test
    public void it_accepts_a_kratos_token_checked_against_its_static_keys() throws JOSEException {
        Jwt jwt = security.jwtDecoder().decode( sign( kratosKey, KRATOS_ISSUER, "identity-id", List.of( AUDIENCE ) ) );

        Assert.assertEquals( "identity-id", jwt.getSubject() );
        Assert.assertEquals( KRATOS_ISSUER, jwt.getClaimAsString( "iss" ) );
    }


    @Test
    public void it_accepts_a_hydra_token_checked_against_its_jwks_endpoint() throws JOSEException {
        Jwt jwt = security.jwtDecoder().decode( sign( hydraKey, HYDRA_ISSUER, "client-id", List.of( AUDIENCE ) ) );

        Assert.assertEquals( "client-id", jwt.getSubject() );
    }


    /**
     * Each issuer is checked against its own keys only: a key trusted for Hydra does not sign for Kratos.
     */
    @Test
    public void it_rejects_a_token_signed_by_the_key_of_another_issuer() throws JOSEException {
        String token = sign( hydraKey, KRATOS_ISSUER, "identity-id", List.of( AUDIENCE ) );

        Assert.assertThrows( JwtException.class, () -> security.jwtDecoder().decode( token ) );
    }


    @Test
    public void it_rejects_a_token_signed_by_an_unknown_key_carrying_a_known_key_id() throws JOSEException {
        String token = sign( foreignKey, KRATOS_ISSUER, "identity-id", List.of( AUDIENCE ) );

        Assert.assertThrows( JwtException.class, () -> security.jwtDecoder().decode( token ) );
    }


    @Test
    public void it_rejects_a_token_issued_for_another_audience() throws JOSEException {
        String token = sign( kratosKey, KRATOS_ISSUER, "identity-id", List.of( "another-application" ) );

        JwtValidationException exception = Assert.assertThrows( JwtValidationException.class, () -> security.jwtDecoder().decode( token ) );

        Assert.assertTrue( exception.getMessage().contains( "The token is not issued for this audience" ) );
    }


    @Test
    public void it_rejects_a_token_without_audience() throws JOSEException {
        String token = sign( hydraKey, HYDRA_ISSUER, "client-id", List.of() );

        Assert.assertThrows( JwtValidationException.class, () -> security.jwtDecoder().decode( token ) );
    }


    @Test
    public void it_accepts_an_audience_among_several() throws JOSEException {
        Jwt jwt = security.jwtDecoder().decode( sign( kratosKey, KRATOS_ISSUER, "identity-id", List.of( "other", AUDIENCE ) ) );

        Assert.assertEquals( "identity-id", jwt.getSubject() );
    }


    @Test
    public void it_accepts_any_audience_when_none_is_configured() throws JOSEException {
        configure( null );

        Jwt jwt = security.jwtDecoder().decode( sign( kratosKey, KRATOS_ISSUER, "identity-id", List.of( "another-application" ) ) );

        Assert.assertEquals( "identity-id", jwt.getSubject() );
    }


    /**
     * BadJwtException, which Spring Security turns into a 401, not a 500.
     */
    @Test
    public void it_rejects_a_token_issued_by_an_unknown_issuer() {
        BadJwtException exception = Assert.assertThrows(
                BadJwtException.class,
                () -> security.jwtDecoder().decode( tokenIssuedBy( "https://evil.example.com" ) )
        );

        Assert.assertEquals( "Unknown issuer: https://evil.example.com", exception.getMessage() );
    }


    @Test
    public void it_rejects_a_malformed_token() {
        Assert.assertThrows( BadJwtException.class, () -> security.jwtDecoder().decode( "not-a-jwt" ) );
        Assert.assertThrows( BadJwtException.class, () -> security.jwtDecoder().decode( "header.###.signature" ) );
    }


    @Test
    public void it_requires_at_least_one_issuer() {
        SecurityConfigurer.init().build();

        Assert.assertThrows( IllegalStateException.class, () -> security.jwtDecoder() );
    }


    /**
     * The tokenizer signing key is private and must never reach the backend.
     */
    @Test
    public void it_refuses_a_static_jwks_holding_a_private_key() {
        SecurityConfigurer
                .init()
                .addIssuerWithJwks( KRATOS_ISSUER, new JWKSet( kratosKey ).toString( false ) )
                .build();

        Assert.assertThrows( IllegalStateException.class, () -> security.jwtDecoder() );
    }


    @Test
    public void it_refuses_an_invalid_static_jwks() {
        SecurityConfigurer
                .init()
                .addIssuerWithJwks( KRATOS_ISSUER, "not a json web key set" )
                .build();

        Assert.assertThrows( IllegalStateException.class, () -> security.jwtDecoder() );
    }


    private void configure( String audience ) {
        SecurityConfigurer
                .init()
                .addIssuerWithJwks( KRATOS_ISSUER, new JWKSet( kratosKey.toPublicJWK() ).toString() )
                .addIssuer( HYDRA_ISSUER, "http://127.0.0.1:" + hydraJwksServer.getAddress().getPort() + "/.well-known/jwks.json" )
                .setAudience( audience )
                .build();
    }


    private String sign( RSAKey key, String issuer, String subject, List< String > audiences ) throws JOSEException {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer( issuer )
                .subject( subject )
                .audience( audiences )
                .issueTime( new Date() )
                .expirationTime( Date.from( Instant.now().plusSeconds( 300 ) ) )
                .build();

        SignedJWT jwt = new SignedJWT( new JWSHeader.Builder( JWSAlgorithm.RS256 ).keyID( key.getKeyID() ).build(), claims );

        jwt.sign( new RSASSASigner( key ) );

        return jwt.serialize();
    }


    private String tokenIssuedBy( String issuer ) {
        String payload = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString( ( "{\"iss\":\"" + issuer + "\"}" ).getBytes( StandardCharsets.UTF_8 ) );

        return "header." + payload + ".signature";
    }
}
