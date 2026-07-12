package org.romainlavabre.security.session;

import org.romainlavabre.security.BearerTokenExtractor;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.springframework.stereotype.Service;

import java.util.StringJoiner;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class CookieBuilder {
    public static final String REFRESH_TOKEN_COOKIE_NAME = "REFRESH_TOKEN";
    public static final String CLIENT_ID_COOKIE_NAME     = "CLIENT_ID";

    private static final int ONE_YEAR = 60 * 60 * 24 * 365;
    private static final int EXPIRED  = -1;


    public String accessToken( String accessToken ) {
        return build( BearerTokenExtractor.ACCESS_TOKEN_COOKIE_NAME, accessToken, SecurityConfigurer.get().getRootCookiePath() );
    }


    public String refreshToken( String refreshToken ) {
        return build( REFRESH_TOKEN_COOKIE_NAME, refreshToken, SecurityConfigurer.get().getSessionCookiePath() );
    }


    public String clientId( String clientId ) {
        return build( CLIENT_ID_COOKIE_NAME, clientId, SecurityConfigurer.get().getSessionCookiePath() );
    }


    protected String build( String name, String value, String path ) {
        if ( value == null ) {
            value = "";
        }

        String domain = SecurityConfigurer.get().getCookieDomain();

        StringJoiner cookie = new StringJoiner( "; " );
        cookie.add( name + "=" + value );
        cookie.add( "Max-Age=" + ( value.isBlank() ? EXPIRED : ONE_YEAR ) );
        cookie.add( "Path=" + path );
        cookie.add( "HttpOnly" );
        cookie.add( "Secure" );
        cookie.add( "SameSite=" + getSameSite( domain ) );

        // Without a configured domain the cookie stays host only, which is a sane default
        if ( domain != null && !domain.isBlank() ) {
            cookie.add( "Domain=." + domain );
        }

        return cookie.toString();
    }


    protected String getSameSite( String domain ) {
        return SecurityConfigurer.get().getSameSiteNoneDomains().contains( domain ) ? "None" : "Strict";
    }
}
