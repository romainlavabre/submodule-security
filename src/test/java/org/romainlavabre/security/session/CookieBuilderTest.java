package org.romainlavabre.security.session;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.romainlavabre.security.config.SecurityConfigurer;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class CookieBuilderTest {

    private CookieBuilder cookieBuilder;


    @Before
    public void setUp() {
        cookieBuilder = new CookieBuilder();

        SecurityConfigurer
                .init()
                .setCookieDomain( "fairfair.dev" )
                .build();
    }


    @Test
    public void access_token_is_scoped_to_the_whole_application() {
        String cookie = cookieBuilder.accessToken( "a.b.c" );

        Assert.assertTrue( cookie.contains( "ACCESS_TOKEN=a.b.c" ) );
        Assert.assertTrue( cookie.contains( "Path=/;" ) );
        Assert.assertTrue( cookie.contains( "HttpOnly" ) );
        Assert.assertTrue( cookie.contains( "Secure" ) );
        Assert.assertTrue( cookie.contains( "Domain=.fairfair.dev" ) );
    }


    /**
     * The refresh token is replayed by both /auth/refresh and /auth/revoke.
     */
    @Test
    public void refresh_token_and_client_id_are_scoped_to_the_session_endpoints() {
        Assert.assertTrue( cookieBuilder.refreshToken( "token" ).contains( "Path=/auth;" ) );
        Assert.assertTrue( cookieBuilder.clientId( "client" ).contains( "Path=/auth;" ) );
    }


    @Test
    public void a_reverse_proxy_prefix_is_prepended_to_every_cookie_path() {
        SecurityConfigurer
                .init()
                .setCookieDomain( "fairfair.dev" )
                .setReverseProxyPrefix( "/api" )
                .build();

        Assert.assertTrue( cookieBuilder.accessToken( "a.b.c" ).contains( "Path=/api;" ) );
        Assert.assertTrue( cookieBuilder.refreshToken( "token" ).contains( "Path=/api/auth;" ) );
        Assert.assertTrue( cookieBuilder.clientId( "client" ).contains( "Path=/api/auth;" ) );
    }


    @Test
    public void a_reverse_proxy_prefix_is_normalized() {
        SecurityConfigurer
                .init()
                .setCookieDomain( "fairfair.dev" )
                .setReverseProxyPrefix( "api/" )
                .build();

        Assert.assertTrue( cookieBuilder.accessToken( "a.b.c" ).contains( "Path=/api;" ) );
        Assert.assertTrue( cookieBuilder.refreshToken( "token" ).contains( "Path=/api/auth;" ) );
    }


    @Test
    public void a_blank_reverse_proxy_prefix_keeps_the_default_paths() {
        SecurityConfigurer
                .init()
                .setCookieDomain( "fairfair.dev" )
                .setReverseProxyPrefix( "  " )
                .build();

        Assert.assertTrue( cookieBuilder.accessToken( "a.b.c" ).contains( "Path=/;" ) );
        Assert.assertTrue( cookieBuilder.refreshToken( "token" ).contains( "Path=/auth;" ) );
    }


    @Test
    public void a_null_value_expires_the_cookie() {
        String cookie = cookieBuilder.accessToken( null );

        Assert.assertTrue( cookie.contains( "ACCESS_TOKEN=;" ) );
        Assert.assertTrue( cookie.contains( "Max-Age=-1" ) );
    }


    @Test
    public void same_site_is_strict_when_no_domain_is_allowed() {
        Assert.assertTrue( cookieBuilder.accessToken( "a.b.c" ).contains( "SameSite=Strict" ) );
    }


    @Test
    public void same_site_is_none_when_the_domain_is_allowed() {
        SecurityConfigurer
                .init()
                .setCookieDomain( "fairfair.dev" )
                .addSameSiteNoneDomain( "localhost" )
                .addSameSiteNoneDomain( "fairfair.dev" )
                .build();

        Assert.assertTrue( cookieBuilder.accessToken( "a.b.c" ).contains( "SameSite=None" ) );
    }


    @Test
    public void same_site_is_strict_when_the_domain_is_not_allowed() {
        SecurityConfigurer
                .init()
                .setCookieDomain( "air.dev" )
                .addSameSiteNoneDomain( "fairfair.dev" )
                .build();

        Assert.assertTrue( cookieBuilder.accessToken( "a.b.c" ).contains( "SameSite=Strict" ) );
    }


    @Test
    public void the_cookie_stays_host_only_when_no_domain_is_configured() {
        SecurityConfigurer.init().build();

        Assert.assertFalse( cookieBuilder.accessToken( "a.b.c" ).contains( "Domain=" ) );
    }
}
