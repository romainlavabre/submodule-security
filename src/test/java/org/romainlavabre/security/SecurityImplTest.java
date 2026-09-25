package org.romainlavabre.security;

import jakarta.servlet.http.Cookie;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.romainlavabre.request.MockRequest;
import org.romainlavabre.request.Request;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.romainlavabre.security.principal.Principal;
import org.romainlavabre.security.principal.PrincipalResolver;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The caller's identity may only come from a token Spring Security authenticated: reading the payload
 * of any token, on any endpoint, would let an anonymous request pick the sub it wants on the public
 * space.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class SecurityImplTest {

    private static final String SUB         = "0d1f4c6a-7b2e-4d3a-9f8c-1e2b3a4d5c6e";
    private static final String CLIENT_ID   = "c7a1e0f2-3b4d-4c5e-8f6a-7b8c9d0e1f2a";
    private static final String TOKEN       = "header.payload.signature";
    private static final String SECURED_URI = "/prescriber/sale_invoices";
    private static final String PUBLIC_URI  = "/guest/ping";


    @Before
    public void setUp() {
        SecurityConfigurer
                .init()
                .addPublicEndpoint( "/guest/**" )
                .addSecuredEndpoint( "/prescriber/**", "ROLE_PRESCRIBER" )
                .build();
    }


    /**
     * A forged token must not even reach the resolver, whose miss calls the application.
     */
    @Test
    public void it_ignores_a_token_rejected_by_the_decoder() {
        ResolverSpy resolver = new ResolverSpy();

        SecurityImpl security = new SecurityImpl( request( SECURED_URI, TOKEN ), resolver, rejectingDecoder() );

        Assert.assertFalse( security.hasConnected() );
        Assert.assertTrue( resolver.calls.isEmpty() );
    }


    @Test
    public void it_ignores_a_token_rejected_by_the_decoder_when_carried_by_a_cookie() {
        ResolverSpy resolver = new ResolverSpy();

        SecurityImpl security = new SecurityImpl( requestWithCookie( SECURED_URI, TOKEN ), resolver, rejectingDecoder() );

        Assert.assertFalse( security.hasConnected() );
        Assert.assertTrue( resolver.calls.isEmpty() );
    }


    /**
     * A public endpoint resolves no token in the filter chain, so no identity may be built here either,
     * whatever the token is worth.
     */
    @Test
    public void it_stays_anonymous_on_a_public_endpoint_carrying_a_valid_token() {
        ResolverSpy resolver = new ResolverSpy();
        DecoderSpy  decoder  = new DecoderSpy( jwt( Map.of( "sub", SUB ) ) );

        SecurityImpl security = new SecurityImpl( request( PUBLIC_URI, TOKEN ), resolver, decoder );

        Assert.assertFalse( security.hasConnected() );
        Assert.assertTrue( decoder.calls.isEmpty() );
        Assert.assertTrue( resolver.calls.isEmpty() );
    }


    @Test
    public void it_stays_anonymous_on_an_undeclared_endpoint() {
        DecoderSpy decoder = new DecoderSpy( jwt( Map.of( "sub", SUB ) ) );

        SecurityImpl security = new SecurityImpl( request( "/unknown/thing", TOKEN ), new ResolverSpy(), decoder );

        Assert.assertFalse( security.hasConnected() );
        Assert.assertTrue( decoder.calls.isEmpty() );
    }


    @Test
    public void it_stays_anonymous_without_authorization() {
        ResolverSpy resolver = new ResolverSpy();
        DecoderSpy  decoder  = new DecoderSpy( jwt( Map.of( "sub", SUB ) ) );

        SecurityImpl security = new SecurityImpl( request( SECURED_URI, null ), resolver, decoder );

        Assert.assertFalse( security.hasConnected() );
        Assert.assertTrue( decoder.calls.isEmpty() );
        Assert.assertTrue( resolver.calls.isEmpty() );
    }


    /**
     * /userinfo is not declared by the application, but always requires a token.
     */
    @Test
    public void it_resolves_the_caller_on_userinfo() {
        SecurityImpl security = new SecurityImpl( request( "/userinfo", TOKEN ), new ResolverSpy(), new DecoderSpy( jwt( Map.of( "sub", SUB ) ) ) );

        Assert.assertTrue( security.hasConnected() );
    }


    /**
     * Reading an unidentified caller denies rather than throws: a caller forgetting to guard with
     * hasConnected() must not turn into a 500.
     */
    @Test
    public void it_answers_as_an_unidentified_caller_when_anonymous() {
        SecurityImpl security = new SecurityImpl( request( PUBLIC_URI, TOKEN ), new ResolverSpy(), rejectingDecoder() );

        Assert.assertFalse( security.hasRole( "ROLE_PRESCRIBER" ) );
        Assert.assertFalse( security.hasUser() );
        Assert.assertFalse( security.hasClient() );
        Assert.assertFalse( security.hasAttribute( "external_id" ) );
        Assert.assertTrue( security.getRoles().isEmpty() );
        Assert.assertNull( security.getUsername() );
        Assert.assertNull( security.getAttribute( "external_id" ) );
        Assert.assertNull( security.getClientId() );
        Assert.assertEquals( -1, security.getId() );
        Assert.assertEquals( 0, security.getScopes().length );
        Assert.assertFalse( security.hasScope( "invoice:read" ) );
    }


    @Test
    public void it_resolves_a_user_from_an_accepted_token() {
        ResolverSpy resolver = new ResolverSpy();

        SecurityImpl security = new SecurityImpl( request( SECURED_URI, TOKEN ), resolver, new DecoderSpy( jwt( Map.of( "sub", SUB ) ) ) );

        Assert.assertTrue( security.hasConnected() );
        Assert.assertTrue( security.hasUser() );
        Assert.assertFalse( security.hasClient() );
        Assert.assertEquals( SUB, security.getAuthenticationId() );
        Assert.assertEquals( "user@marea-conseil.fr", security.getUsername() );
        Assert.assertEquals( List.of( SUB ), resolver.calls );
        Assert.assertEquals( List.of( "ROLE_PRESCRIBER" ), security.getRoles() );
        Assert.assertTrue( security.hasRole( "ROLE_PRESCRIBER" ) );
        Assert.assertEquals( 42, security.getId() );
    }


    @Test
    public void it_resolves_a_client_from_an_accepted_token() {
        SecurityImpl security = new SecurityImpl(
                request( SECURED_URI, TOKEN ),
                new ResolverSpy(),
                new DecoderSpy( jwt( Map.of( "sub", CLIENT_ID, "client_id", CLIENT_ID ) ) )
        );

        Assert.assertTrue( security.hasClient() );
        Assert.assertFalse( security.hasUser() );
        Assert.assertEquals( CLIENT_ID, security.getClientId() );
        Assert.assertNull( security.getUsername() );
    }


    @Test
    public void it_reads_the_client_id_from_azp_first() {
        SecurityImpl security = new SecurityImpl(
                request( SECURED_URI, TOKEN ),
                new ResolverSpy(),
                new DecoderSpy( jwt( Map.of( "sub", SUB, "azp", "from-azp", "client_id", "from-client-id" ) ) )
        );

        Assert.assertEquals( "from-azp", security.getClientId() );
    }


    /**
     * Hydra names the granted scopes scp, as an array.
     */
    @Test
    public void it_reads_the_scopes_hydra_carries_on_scp() {
        SecurityImpl security = new SecurityImpl(
                request( SECURED_URI, TOKEN ),
                new ResolverSpy(),
                new DecoderSpy( jwt( Map.of( "sub", SUB, "scp", List.of( "invoice:read", "invoice:write" ) ) ) )
        );

        Assert.assertArrayEquals( new String[]{ "invoice:read", "invoice:write" }, security.getScopes() );
        Assert.assertTrue( security.hasScope( "invoice:write" ) );
    }


    @Test
    public void it_answers_no_scope_when_the_token_carries_none() {
        SecurityImpl security = new SecurityImpl( request( SECURED_URI, TOKEN ), new ResolverSpy(), new DecoderSpy( jwt( Map.of( "sub", SUB ) ) ) );

        Assert.assertEquals( 0, security.getScopes().length );
        Assert.assertFalse( security.hasScope( "invoice:read" ) );
    }


    private Request request( String uri, String token ) {
        RequestStub request = new RequestStub( uri );

        if ( token != null ) {
            request.setHeader( "Authorization", "Bearer " + token );
        }

        return request;
    }


    private Request requestWithCookie( String uri, String token ) {
        RequestStub request = new RequestStub( uri );

        request.setCookies( new Cookie( BearerTokenExtractor.ACCESS_TOKEN_COOKIE_NAME, token ) );

        return request;
    }


    private Jwt jwt( Map< String, Object > claims ) {
        Jwt.Builder builder = Jwt.withTokenValue( TOKEN ).header( "alg", "RS256" );

        claims.forEach( builder::claim );

        return builder.build();
    }


    private JwtDecoder rejectingDecoder() {
        return token -> {
            throw new JwtException( "Invalid signature" );
        };
    }


    /**
     * MockRequest hardcodes its uri and answers no cookie.
     */
    private static class RequestStub extends MockRequest {
        private final String uri;

        private Cookie[] cookies;


        private RequestStub( String uri ) {
            this.uri     = uri;
            this.cookies = new Cookie[ 0 ];
        }


        private void setCookies( Cookie... cookies ) {
            this.cookies = cookies;
        }


        @Override
        public String getUri() {
            return uri;
        }


        @Override
        public Cookie[] getCookies() {
            return cookies;
        }
    }


    private static class DecoderSpy implements JwtDecoder {
        private final Jwt            jwt;
        private final List< String > calls = new ArrayList<>();


        private DecoderSpy( Jwt jwt ) {
            this.jwt = jwt;
        }


        @Override
        public Jwt decode( String token ) {
            calls.add( token );

            return jwt;
        }
    }


    /**
     * Same discriminator as the real resolver: a sub equal to the client id is a client.
     */
    private static class ResolverSpy implements PrincipalResolver {
        private final List< String > calls = new ArrayList<>();


        @Override
        public Principal resolve( Jwt jwt ) {
            return resolve( jwt.getClaims() );
        }


        @Override
        public Principal resolve( Map< String, Object > claims ) {
            String sub = claims.get( "sub" ).toString();

            calls.add( sub );

            if ( isClient( claims ) ) {
                return new Principal( sub, Principal.Type.CLIENT, List.of( "ROLE_PRESCRIBER" ), Map.of(), null );
            }

            return new Principal( sub, Principal.Type.USER, List.of( "ROLE_PRESCRIBER" ), Map.of( "external_id", "42" ), "user@marea-conseil.fr" );
        }


        @Override
        public boolean isClient( Map< String, Object > claims ) {
            return claims.get( "sub" ).equals( claims.get( "client_id" ) );
        }
    }
}
