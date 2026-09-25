package org.romainlavabre.security;

import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The two claims whose shape depends on the issuer. Reading them wrong either invents a grant the
 * client never received, or drops one it did — both decide an authorization.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class TokenClaimsTest {

    @Test
    public void it_reads_the_audience_carried_as_an_array() {
        Assert.assertEquals(
                List.of( "marea", "other" ),
                TokenClaims.audiences( claims( "aud", List.of( "marea", "other" ) ) )
        );
    }


    /**
     * An issuer minting a token for a single audience is allowed to emit it as a bare string.
     */
    @Test
    public void it_reads_the_audience_carried_as_a_single_string() {
        Assert.assertEquals( List.of( "marea" ), TokenClaims.audiences( claims( "aud", "marea" ) ) );
    }


    /**
     * An audience is one value, never a list packed into a string: splitting it would grant two
     * audiences where the issuer named one, neither of them the one it meant.
     */
    @Test
    public void it_never_splits_an_audience_on_its_spaces() {
        Assert.assertEquals( List.of( "marea conseil" ), TokenClaims.audiences( claims( "aud", "marea conseil" ) ) );
    }


    @Test
    public void it_answers_no_audience_rather_than_throwing() {
        Assert.assertTrue( TokenClaims.audiences( Map.of() ).isEmpty() );
        Assert.assertTrue( TokenClaims.audiences( null ).isEmpty() );
        Assert.assertTrue( TokenClaims.audiences( claims( "aud", "" ) ).isEmpty() );
        Assert.assertTrue( TokenClaims.audiences( claims( "aud", List.of() ) ).isEmpty() );
    }


    @Test
    public void it_reads_the_scopes_hydra_emits_as_an_array() {
        Assert.assertEquals(
                List.of( "invoice:read", "invoice:write" ),
                TokenClaims.scopes( claims( "scp", List.of( "invoice:read", "invoice:write" ) ) )
        );
    }


    @Test
    public void it_reads_the_scopes_carried_as_a_space_separated_string() {
        Assert.assertEquals(
                List.of( "invoice:read", "invoice:write" ),
                TokenClaims.scopes( claims( "scope", "invoice:read  invoice:write" ) )
        );
    }


    @Test
    public void it_prefers_scp_over_scope_when_both_are_present() {
        Map< String, Object > claims = claims( "scp", List.of( "invoice:read" ) );
        claims.put( "scope", "all:read all:write" );

        Assert.assertEquals( List.of( "invoice:read" ), TokenClaims.scopes( claims ) );
    }


    @Test
    public void it_answers_no_scope_rather_than_throwing() {
        Assert.assertTrue( TokenClaims.scopes( Map.of() ).isEmpty() );
        Assert.assertTrue( TokenClaims.scopes( null ).isEmpty() );
        Assert.assertTrue( TokenClaims.scopes( claims( "scope", "   " ) ).isEmpty() );
    }


    @Test
    public void it_matches_a_scope_whatever_its_case() {
        Assert.assertTrue( TokenClaims.hasScope( claims( "scp", List.of( "Invoice:Read" ) ), "invoice:read" ) );
    }


    @Test
    public void it_matches_any_of_the_expected_scopes() {
        Map< String, Object > claims = claims( "scp", List.of( "all:read" ) );

        Assert.assertTrue( TokenClaims.hasAnyScope( claims, "invoice:read", "all:read" ) );
        Assert.assertFalse( TokenClaims.hasAnyScope( claims, "invoice:write", "all:write" ) );
    }


    private Map< String, Object > claims( String name, Object value ) {
        Map< String, Object > claims = new HashMap<>();

        claims.put( name, value );

        return claims;
    }
}
