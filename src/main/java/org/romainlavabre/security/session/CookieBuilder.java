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
    public static final String KRATOS_FLOW_COOKIE_NAME   = "KRATOS_FLOW";

    private static final int ONE_YEAR       = 60 * 60 * 24 * 365;
    private static final int FIFTEEN_MINUTE = 60 * 15;
    private static final int EXPIRED        = -1;


    public String accessToken( String accessToken ) {
        return build( BearerTokenExtractor.ACCESS_TOKEN_COOKIE_NAME, accessToken, SecurityConfigurer.get().getRootCookiePath(), ONE_YEAR );
    }


    /**
     * Holds the Kratos session token, the durable credential: Ory issues no refresh token.
     */
    public String refreshToken( String refreshToken ) {
        return build( REFRESH_TOKEN_COOKIE_NAME, refreshToken, SecurityConfigurer.get().getSessionCookiePath(), ONE_YEAR );
    }


    /**
     * Holds the Kratos login flow id between the two steps of the OTP login (/auth/login then
     * /auth/login/verify). Its lifespan matches the one of the Kratos login flow (15 min).
     */
    public String kratosFlow( String flowId ) {
        return build( KRATOS_FLOW_COOKIE_NAME, flowId, SecurityConfigurer.get().getSessionCookiePath(), FIFTEEN_MINUTE );
    }


    protected String build( String name, String value, String path, int maxAge ) {
        if ( value == null ) {
            value = "";
        }

        String domain = SecurityConfigurer.get().getCookieDomain();

        StringJoiner cookie = new StringJoiner( "; " );
        cookie.add( name + "=" + value );
        cookie.add( "Max-Age=" + ( value.isBlank() ? EXPIRED : maxAge ) );
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
