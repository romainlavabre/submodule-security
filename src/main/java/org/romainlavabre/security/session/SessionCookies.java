package org.romainlavabre.security.session;

import jakarta.servlet.http.Cookie;
import org.romainlavabre.exception.HttpBadRequestException;
import org.romainlavabre.exception.HttpNotFoundException;
import org.romainlavabre.request.Request;
import org.romainlavabre.security.message.Error;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public record SessionCookies( String clientId, String refreshToken ) {

    public static SessionCookies read( Request request ) {
        Cookie[] cookies = request.getCookies();

        if ( cookies == null ) {
            throw new HttpBadRequestException( Error.IDP_NO_ACTIVE_SESSION, false );
        }

        String clientId     = null;
        String refreshToken = null;

        for ( Cookie cookie : cookies ) {
            if ( CookieBuilder.CLIENT_ID_COOKIE_NAME.equals( cookie.getName() ) ) {
                clientId = cookie.getValue();
            }

            if ( CookieBuilder.REFRESH_TOKEN_COOKIE_NAME.equals( cookie.getName() ) ) {
                refreshToken = cookie.getValue();
            }
        }

        if ( refreshToken == null || refreshToken.isBlank() ) {
            throw new HttpBadRequestException( Error.IDP_NO_ACTIVE_SESSION, false );
        }

        if ( clientId == null || clientId.isBlank() ) {
            throw new HttpNotFoundException( Error.IDP_CLIENT_NOT_FOUND, false );
        }

        return new SessionCookies( clientId, refreshToken );
    }
}
