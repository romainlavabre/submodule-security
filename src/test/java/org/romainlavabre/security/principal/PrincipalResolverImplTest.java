package org.romainlavabre.security.principal;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.romainlavabre.security.config.SecurityConfigurer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class PrincipalResolverImplTest {

    private static final String SUB       = "0d1f4c6a-7b2e-4d3a-9f8c-1e2b3a4d5c6e";
    private static final String CLIENT_ID = "5tj9k2m4n6p8q1r3s5t7u9v1w3";


    @Before
    public void setUp() {
        SecurityConfigurer.init().build();
    }


    @Test
    public void it_resolves_an_identity_when_the_sub_differs_from_the_client_id() {
        ProviderSpy       provider = new ProviderSpy();
        PrincipalResolver resolver = new PrincipalResolverImpl( provider );

        Principal principal = resolver.resolve( claims( SUB, CLIENT_ID ) );

        Assert.assertEquals( Principal.Type.USER, principal.getType() );
        Assert.assertEquals( List.of( "ROLE_ADMIN" ), principal.getRoles() );
        Assert.assertEquals( List.of( SUB ), provider.identityCalls );
        Assert.assertTrue( provider.clientCalls.isEmpty() );
    }


    /**
     * A client_credentials token carries no user identity. Both shapes must land on the client
     * branch: getting this wrong hands the roles of a client to a user.
     */
    @Test
    public void it_resolves_a_client_when_the_sub_is_absent() {
        ProviderSpy provider = new ProviderSpy();

        Principal principal = new PrincipalResolverImpl( provider ).resolve( claims( null, CLIENT_ID ) );

        Assert.assertEquals( Principal.Type.CLIENT, principal.getType() );
        Assert.assertEquals( List.of( CLIENT_ID ), provider.clientCalls );
        Assert.assertTrue( provider.identityCalls.isEmpty() );
    }


    @Test
    public void it_resolves_a_client_when_the_sub_equals_the_client_id() {
        ProviderSpy provider = new ProviderSpy();

        Principal principal = new PrincipalResolverImpl( provider ).resolve( claims( CLIENT_ID, CLIENT_ID ) );

        Assert.assertEquals( Principal.Type.CLIENT, principal.getType() );
        Assert.assertEquals( List.of( CLIENT_ID ), provider.clientCalls );
        Assert.assertTrue( provider.identityCalls.isEmpty() );
    }


    @Test
    public void it_reads_the_client_id_from_azp_over_client_id() {
        ProviderSpy           provider = new ProviderSpy();
        Map< String, Object > claims   = claims( null, "ignored" );
        claims.put( "azp", CLIENT_ID );

        new PrincipalResolverImpl( provider ).resolve( claims );

        Assert.assertEquals( List.of( CLIENT_ID ), provider.clientCalls );
    }


    @Test
    public void it_hits_the_cache_on_a_second_resolve() {
        ProviderSpy       provider = new ProviderSpy();
        PrincipalResolver resolver = new PrincipalResolverImpl( provider );

        resolver.resolve( claims( SUB, CLIENT_ID ) );
        resolver.resolve( claims( SUB, CLIENT_ID ) );

        Assert.assertEquals( 1, provider.identityCalls.size() );
    }


    /**
     * An identity and a client sharing an id must not share a cache entry.
     */
    @Test
    public void it_never_collides_identity_and_client_keys() {
        ProviderSpy       provider = new ProviderSpy();
        PrincipalResolver resolver = new PrincipalResolverImpl( provider );

        resolver.resolve( claims( CLIENT_ID, CLIENT_ID ) );
        resolver.resolve( claims( CLIENT_ID, "another-client" ) );

        Assert.assertEquals( List.of( CLIENT_ID ), provider.clientCalls );
        Assert.assertEquals( List.of( CLIENT_ID ), provider.identityCalls );
    }


    /**
     * A deleted identity must deny, not answer 500 on every call.
     */
    @Test
    public void it_resolves_without_any_role_when_not_found() {
        ProviderSpy provider = new ProviderSpy();
        provider.found = false;

        Principal principal = new PrincipalResolverImpl( provider ).resolve( claims( SUB, CLIENT_ID ) );

        Assert.assertEquals( SUB, principal.getId() );
        Assert.assertEquals( Principal.Type.USER, principal.getType() );
        Assert.assertTrue( principal.getRoles().isEmpty() );
        Assert.assertTrue( principal.getAttributes().isEmpty() );
    }


    /**
     * RAM is a constant we pick, not a function of the user count. Caffeine evicts on an amortized
     * basis, cleanUp forces the pending maintenance rather than waiting for it.
     */
    @Test
    public void it_bounds_the_cache_to_its_max_size() {
        SecurityConfigurer.init().setPrincipalCacheMaxSize( 10 ).build();

        PrincipalResolverImpl resolver = new PrincipalResolverImpl( new ProviderSpy() );

        for ( int i = 0; i < 5_000; i++ ) {
            resolver.resolve( claims( "sub-" + i, CLIENT_ID ) );
        }

        resolver.cache().cleanUp();

        long size = resolver.cache().estimatedSize();

        Assert.assertTrue( "cache grew to " + size + " despite a maximum size of 10", size <= 10 );
    }


    @Test
    public void it_misses_the_cache_once_past_its_ttl() throws InterruptedException {
        SecurityConfigurer.init().setPrincipalCacheTtlSeconds( 1 ).build();

        ProviderSpy       provider = new ProviderSpy();
        PrincipalResolver resolver = new PrincipalResolverImpl( provider );

        resolver.resolve( claims( SUB, CLIENT_ID ) );
        Thread.sleep( 1_100 );
        resolver.resolve( claims( SUB, CLIENT_ID ) );

        Assert.assertEquals( 2, provider.identityCalls.size() );
    }


    private Map< String, Object > claims( String sub, String clientId ) {
        Map< String, Object > claims = new HashMap<>();

        if ( sub != null ) {
            claims.put( "sub", sub );
        }

        if ( clientId != null ) {
            claims.put( "client_id", clientId );
        }

        return claims;
    }


    private static class ProviderSpy implements PrincipalProvider {
        private final List< String > identityCalls = new ArrayList<>();
        private final List< String > clientCalls   = new ArrayList<>();
        private       boolean        found         = true;


        @Override
        public Principal findIdentity( String idpId ) {
            identityCalls.add( idpId );

            return found
                    ? new Principal( idpId, Principal.Type.USER, List.of( "ROLE_ADMIN" ), Map.of( "external_id", "42" ), "a@b.fr" )
                    : null;
        }


        @Override
        public Principal findClient( String clientId ) {
            clientCalls.add( clientId );

            return found
                    ? new Principal( clientId, Principal.Type.CLIENT, List.of( "ROLE_PRESCRIBER" ), Map.of(), null )
                    : null;
        }
    }
}
