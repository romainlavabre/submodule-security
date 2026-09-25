package org.romainlavabre.security.session;

import jakarta.servlet.http.Cookie;
import org.romainlavabre.request.Request;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public final class SessionCookies {

    /**
     * @return The Kratos session token, null when the caller holds none
     */
    public static String readSessionToken( Request request ) {
        return read( request, CookieBuilder.REFRESH_TOKEN_COOKIE_NAME );
    }


    /**
     * @return The Kratos login flow id, null when the caller holds none
     */
    public static String readKratosFlow( Request request ) {
        return read( request, CookieBuilder.KRATOS_FLOW_COOKIE_NAME );
    }


    private static String read( Request request, String name ) {
        Cookie[] cookies = request.getCookies();

        if ( cookies == null ) {
            return null;
        }

        String value = null;

        for ( Cookie cookie : cookies ) {
            if ( name.equals( cookie.getName() ) ) {
                value = cookie.getValue();
            }
        }

        return value == null || value.isBlank() ? null : value;
    }


    private SessionCookies() {
    }
}
