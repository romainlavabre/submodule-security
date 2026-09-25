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
 * Feeds the claim shapes each Ory issuer emits, and asserts the branch taken by the discriminator,
 * which only reads {@code sub}, {@code azp} and {@code client_id}.
 * <p>
 * Constraint it pins: the Kratos tokenizer template used for USERS must NOT emit a {@code client_id}
 * or {@code azp} claim equal to its {@code sub}, otherwise a user would be read as a client and would
 * inherit its roles. See it_pins_the_kratos_tokenizer_contract.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class PrincipalResolverOryTokenShapeTest {

    /**
     * A Kratos identity id (UUID).
     */
    private static final String KRATOS_SUB = "b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d";

    /**
     * A Hydra client id, for client_credentials Hydra sets sub = client_id.
     */
    private static final String HYDRA_CLIENT_ID = "c7a1e0f2-3b4d-4c5e-8f6a-7b8c9d0e1f2a";


    @Before
    public void setUp() {
        SecurityConfigurer.init().build();
    }


    /**
     * Kratos user token (tokenizer): sub = identity UUID, no client_id nor azp.
     */
    @Test
    public void it_resolves_a_kratos_user_token_as_a_user() {
        ProviderSpy           provider = new ProviderSpy();
        PrincipalResolver     resolver = new PrincipalResolverImpl( provider );
        Map< String, Object > claims   = kratosUserClaims();

        Principal principal = resolver.resolve( claims );

        Assert.assertFalse( resolver.isClient( claims ) );
        Assert.assertEquals( Principal.Type.USER, principal.getType() );
        Assert.assertEquals( List.of( KRATOS_SUB ), provider.identityCalls );
        Assert.assertTrue( "a Kratos user token must never hit the client branch", provider.clientCalls.isEmpty() );
    }


    /**
     * The claims emitted by the Marea tokenizer template (sid, email, aud) must not flip the
     * classification.
     */
    @Test
    public void it_keeps_a_kratos_user_token_carrying_its_traits_a_user() {
        Map< String, Object > claims = kratosUserClaims();
        claims.put( "sid", "3a2b1c0d-9e8f-7a6b-5c4d-3e2f1a0b9c8d" );
        claims.put( "email", "artisan@marea-conseil.fr" );
        claims.put( "aud", List.of( "marea" ) );

        Assert.assertFalse( new PrincipalResolverImpl( new ProviderSpy() ).isClient( claims ) );
    }


    /**
     * Hydra client_credentials access token: sub = client_id, client_id claim present, scp array.
     */
    @Test
    public void it_resolves_a_hydra_client_credentials_token_as_a_client() {
        ProviderSpy           provider = new ProviderSpy();
        PrincipalResolver     resolver = new PrincipalResolverImpl( provider );
        Map< String, Object > claims   = hydraClientClaims();

        Principal principal = resolver.resolve( claims );

        Assert.assertTrue( resolver.isClient( claims ) );
        Assert.assertEquals( Principal.Type.CLIENT, principal.getType() );
        Assert.assertEquals( List.of( HYDRA_CLIENT_ID ), provider.clientCalls );
        Assert.assertTrue( "a Hydra client token must never hit the identity branch", provider.identityCalls.isEmpty() );
    }


    /**
     * Hydra names the client on the client_id claim, with no azp on a client_credentials access token.
     */
    @Test
    public void it_resolves_a_hydra_client_from_its_client_id_claim_without_azp() {
        ProviderSpy           provider = new ProviderSpy();
        Map< String, Object > claims   = hydraClientClaims();

        Assert.assertFalse( "sanity: a Hydra client token has no azp", claims.containsKey( "azp" ) );

        new PrincipalResolverImpl( provider ).resolve( claims );

        Assert.assertEquals( List.of( HYDRA_CLIENT_ID ), provider.clientCalls );
    }


    /**
     * Documents the failure mode, so that it stays visible: a user token wrongly carrying client_id ==
     * sub IS read as a client. The mitigation lives in the Kratos tokenizer template, not in this module.
     */
    @Test
    public void it_pins_the_kratos_tokenizer_contract() {
        PrincipalResolver resolver = new PrincipalResolverImpl( new ProviderSpy() );

        Assert.assertFalse( "well-formed Kratos user token → USER", resolver.isClient( kratosUserClaims() ) );

        Map< String, Object > misTemplated = kratosUserClaims();
        misTemplated.put( "client_id", KRATOS_SUB );

        Assert.assertTrue(
                "a Kratos user token emitting client_id == sub is read as a client — the tokenizer template must not do this",
                resolver.isClient( misTemplated )
        );
    }


    private Map< String, Object > kratosUserClaims() {
        Map< String, Object > claims = new HashMap<>();
        claims.put( "iss", "http://kratos:4433/" );
        claims.put( "sub", KRATOS_SUB );
        claims.put( "exp", 1_900_000_000 );
        claims.put( "iat", 1_899_999_000 );

        return claims;
    }


    private Map< String, Object > hydraClientClaims() {
        Map< String, Object > claims = new HashMap<>();
        claims.put( "iss", "http://hydra:4444/" );
        claims.put( "sub", HYDRA_CLIENT_ID );
        claims.put( "client_id", HYDRA_CLIENT_ID );
        claims.put( "aud", List.of( "marea" ) );
        claims.put( "scp", List.of() );
        claims.put( "exp", 1_900_000_000 );
        claims.put( "iat", 1_899_999_000 );

        return claims;
    }


    private static class ProviderSpy implements PrincipalProvider {
        private final List< String > identityCalls = new ArrayList<>();
        private final List< String > clientCalls   = new ArrayList<>();


        @Override
        public Principal findIdentity( String idpId ) {
            identityCalls.add( idpId );

            return new Principal( idpId, Principal.Type.USER, List.of( "ROLE_BILLER" ), Map.of(), "artisan@marea-conseil.fr" );
        }


        @Override
        public Principal findClient( String clientId ) {
            clientCalls.add( clientId );

            return new Principal( clientId, Principal.Type.CLIENT, List.of( "ROLE_PRESCRIBER" ), Map.of(), null );
        }
    }
}
