package org.romainlavabre.security.config;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class SecurityConfigurerTest {

    /**
     * Without an audience there is nothing to check a client token against.
     */
    @Test
    public void it_refuses_to_require_client_scopes_without_an_audience() {
        SecurityConfigurer securityConfigurer = SecurityConfigurer.init().requireClientScopes();

        Assert.assertThrows( IllegalStateException.class, securityConfigurer::build );
    }


    @Test
    public void it_names_the_client_scopes_after_the_audience_by_default() {
        SecurityConfigurer securityConfigurer = SecurityConfigurer.init().setAudience( "marea" ).requireClientScopes();

        securityConfigurer.build();

        Assert.assertTrue( securityConfigurer.isClientScopesRequired() );
        Assert.assertEquals( "marea", securityConfigurer.getClientScopePrefix() );
    }


    @Test
    public void it_names_the_client_scopes_after_the_prefix_when_set() {
        SecurityConfigurer securityConfigurer = SecurityConfigurer.init().setAudience( "marea" ).setClientScopePrefix( "billing" );

        Assert.assertEquals( "billing", securityConfigurer.getClientScopePrefix() );
    }


    @Test
    public void it_does_not_require_client_scopes_by_default() {
        Assert.assertFalse( SecurityConfigurer.init().isClientScopesRequired() );
    }
}
