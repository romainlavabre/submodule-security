package org.romainlavabre.security;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class RoleNormalizerTest {

    @Test
    public void it_prefixes_a_raw_cognito_group() {
        Assert.assertEquals( "ROLE_ADMIN", RoleNormalizer.normalize( "ADMIN" ) );
    }


    @Test
    public void it_is_idempotent_on_an_already_prefixed_group() {
        Assert.assertEquals( "ROLE_ADMIN", RoleNormalizer.normalize( "ROLE_ADMIN" ) );
    }


    @Test
    public void it_normalizes_every_group() {
        Assert.assertEquals(
                List.of( "ROLE_ADMIN", "ROLE_SELLER", "ROLE_SYSTEM" ),
                RoleNormalizer.normalize( List.of( "ADMIN", "ROLE_SELLER", "SYSTEM" ) )
        );
    }


    /**
     * A machine to machine token carries no cognito:groups claim.
     */
    @Test
    public void it_returns_an_empty_list_when_no_group_is_provided() {
        Assert.assertTrue( RoleNormalizer.normalize( ( List< String > ) null ).isEmpty() );
    }
}
