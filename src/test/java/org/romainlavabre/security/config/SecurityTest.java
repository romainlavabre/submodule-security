package org.romainlavabre.security.config;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.romainlavabre.security.CognitoClaim;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class SecurityTest {
    private static final String ISSUER   = "https://cognito-idp.eu-west-3.amazonaws.com/eu-west-3_known";
    private static final String JWKS_URI = ISSUER + "/.well-known/jwks.json";

    private Security security;


    @Before
    public void setUp() {
        security = new Security();

        SecurityConfigurer
                .init()
                .addIssuer( ISSUER, JWKS_URI )
                .build();
    }


    private Jwt jwt( Map< String, Object > claims ) {
        Jwt.Builder builder = Jwt.withTokenValue( "token" ).header( "alg", "RS256" );

        claims.forEach( builder::claim );

        return builder.build();
    }


    private String tokenIssuedBy( String issuer ) {
        String payload = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString( ( "{\"iss\":\"" + issuer + "\"}" ).getBytes( StandardCharsets.UTF_8 ) );

        return "header." + payload + ".signature";
    }


    @Test
    public void it_accepts_an_access_token() {
        OAuth2TokenValidator< Jwt > validator = security.getAccessTokenValidator();

        Assert.assertFalse( validator.validate( jwt( Map.of( CognitoClaim.TOKEN_USE, "access" ) ) ).hasErrors() );
    }


    /**
     * An id token carries the same cognito:groups claim, it must not authorize a request.
     */
    @Test
    public void it_rejects_an_id_token() {
        OAuth2TokenValidator< Jwt > validator = security.getAccessTokenValidator();

        Assert.assertTrue( validator.validate( jwt( Map.of( CognitoClaim.TOKEN_USE, "id" ) ) ).hasErrors() );
    }


    @Test
    public void it_rejects_a_token_without_token_use() {
        OAuth2TokenValidator< Jwt > validator = security.getAccessTokenValidator();

        Assert.assertTrue( validator.validate( jwt( Map.of( CognitoClaim.SUBJECT, "sub" ) ) ).hasErrors() );
    }


    @Test
    public void it_accepts_any_client_id_when_none_is_registered() {
        OAuth2TokenValidator< Jwt > validator = security.getClientIdValidator();

        Assert.assertFalse( validator.validate( jwt( Map.of( CognitoClaim.CLIENT_ID, "anything" ) ) ).hasErrors() );
    }


    @Test
    public void it_rejects_a_token_issued_for_an_unregistered_client() {
        SecurityConfigurer
                .init()
                .addIssuer( ISSUER, JWKS_URI )
                .addAllowedClientId( "allowed" )
                .build();

        OAuth2TokenValidator< Jwt > validator = security.getClientIdValidator();

        Assert.assertFalse( validator.validate( jwt( Map.of( CognitoClaim.CLIENT_ID, "allowed" ) ) ).hasErrors() );
        Assert.assertTrue( validator.validate( jwt( Map.of( CognitoClaim.CLIENT_ID, "other" ) ) ).hasErrors() );
    }


    @Test
    public void it_rejects_a_token_issued_by_an_unknown_issuer() {
        JwtDecoder decoder = security.jwtDecoder();

        JwtException exception = Assert.assertThrows(
                JwtException.class,
                () -> decoder.decode( tokenIssuedBy( "https://evil.example.com" ) )
        );

        Assert.assertEquals( "Unknown issuer: https://evil.example.com", exception.getMessage() );
    }


    @Test
    public void it_rejects_a_malformed_token() {
        JwtDecoder decoder = security.jwtDecoder();

        Assert.assertThrows( JwtException.class, () -> decoder.decode( "not-a-jwt" ) );
    }


    @Test
    public void it_requires_at_least_one_issuer() {
        SecurityConfigurer.init().build();

        Assert.assertThrows( IllegalStateException.class, () -> security.jwtDecoder() );
    }
}
