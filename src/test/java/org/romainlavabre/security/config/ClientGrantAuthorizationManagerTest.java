package org.romainlavabre.security.config;

import org.junit.Assert;
import org.junit.Test;
import org.romainlavabre.security.principal.PrincipalResolverImpl;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class ClientGrantAuthorizationManagerTest {
    private static final String AUDIENCE  = "marea";
    private static final String CLIENT_ID = "4f7c1d2e-9a3b-4c5d-8e6f-7a8b9c0d1e2f";
    private static final String USER_ID   = "0d1f4c6a-7b2e-4d3a-9f8c-1e2b3a4d5c6e";

    private final ClientGrantAuthorizationManager manager =
            new ClientGrantAuthorizationManager( new PrincipalResolverImpl( null ), AUDIENCE, AUDIENCE );


    @Test
    public void it_never_checks_a_user_token() {
        Assert.assertTrue( granted( userToken(), "POST" ) );
    }


    /**
     * The composed role rule decides for a caller authenticated otherwise than by a token.
     */
    @Test
    public void it_abstains_on_a_non_jwt_authentication() {
        Authentication basic = new UsernamePasswordAuthenticationToken( "system", "secret", List.of() );

        Assert.assertTrue( manager.authorize( () -> basic, context( "POST" ) ).isGranted() );
    }


    @Test
    public void it_denies_a_client_token_without_the_audience() {
        Assert.assertFalse( granted( clientToken( List.of( "another-application" ), "marea:read marea:write" ), "GET" ) );
    }


    @Test
    public void it_grants_a_read_with_the_read_scope() {
        Jwt token = clientToken( List.of( AUDIENCE ), List.of( "marea:read" ) );

        Assert.assertTrue( granted( token, "GET" ) );
        Assert.assertTrue( granted( token, "HEAD" ) );
        Assert.assertTrue( granted( token, "OPTIONS" ) );
    }


    @Test
    public void it_requires_the_write_scope_on_any_other_method() {
        Jwt readOnly = clientToken( List.of( AUDIENCE ), List.of( "marea:read" ) );

        Assert.assertFalse( granted( readOnly, "POST" ) );
        Assert.assertFalse( granted( readOnly, "PATCH" ) );
        Assert.assertFalse( granted( readOnly, "PUT" ) );
        Assert.assertFalse( granted( readOnly, "DELETE" ) );

        Assert.assertTrue( granted( clientToken( List.of( AUDIENCE ), List.of( "marea:write" ) ), "POST" ) );
    }


    @Test
    public void it_does_not_grant_a_read_on_the_write_scope_alone() {
        Assert.assertFalse( granted( clientToken( List.of( AUDIENCE ), List.of( "marea:write" ) ), "GET" ) );
    }


    @Test
    public void it_denies_a_client_token_without_any_scope() {
        Assert.assertFalse( granted( clientToken( List.of( AUDIENCE ), List.of() ), "GET" ) );
    }


    @Test
    public void it_reads_the_scope_claim_as_a_space_separated_string() {
        Assert.assertTrue( granted( clientToken( List.of( AUDIENCE ), "marea:read marea:write" ), "PATCH" ) );
    }


    @Test
    public void it_names_the_scopes_after_the_configured_prefix() {
        ClientGrantAuthorizationManager prefixed =
                new ClientGrantAuthorizationManager( new PrincipalResolverImpl( null ), AUDIENCE, "billing" );

        Jwt token = clientToken( List.of( AUDIENCE ), List.of( "billing:read" ) );

        Assert.assertTrue( prefixed.authorize( () -> new JwtAuthenticationToken( token ), context( "GET" ) ).isGranted() );
        Assert.assertFalse( granted( token, "GET" ) );
    }


    private boolean granted( Jwt token, String method ) {
        return manager.authorize( () -> new JwtAuthenticationToken( token ), context( method ) ).isGranted();
    }


    private RequestAuthorizationContext context( String method ) {
        return new RequestAuthorizationContext( new MockHttpServletRequest( method, "/prescriber/sale_invoices" ) );
    }


    private Jwt userToken() {
        Map< String, Object > claims = new HashMap<>();
        claims.put( "sub", USER_ID );
        claims.put( "aud", List.of( AUDIENCE ) );

        return jwt( claims );
    }


    /**
     * Shaped as Hydra mints it: the sub is the client id.
     */
    private Jwt clientToken( List< String > audiences, Object scopes ) {
        Map< String, Object > claims = new HashMap<>();
        claims.put( "sub", CLIENT_ID );
        claims.put( "client_id", CLIENT_ID );
        claims.put( "aud", audiences );
        claims.put( scopes instanceof String ? "scope" : "scp", scopes );

        return jwt( claims );
    }


    private Jwt jwt( Map< String, Object > claims ) {
        return new Jwt( "token", Instant.now(), Instant.now().plusSeconds( 300 ), Map.of( "alg", "RS256" ), claims );
    }
}
