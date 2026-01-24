package org.romainlavabre.security.cookie;

import org.romainlavabre.request.Request;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.springframework.http.HttpHeaders;

import java.util.StringJoiner;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class CookieBuilder {
    private static final String LOCAL_DOMAIN      = "localhost";
    private static final String ACCESS_TOKEN_URI  = "/";
    private static final String REFRESH_TOKEN_URI = "/api/auth/refresh";


    public static HttpHeaders setCookieToLogin( Request request, String accessToken, String refreshToken ) {
        String origin = request.getHeader( "origin" );

        HttpHeaders headers = new HttpHeaders();

        StringJoiner accessTokenCookie = new StringJoiner( "; " );
        accessTokenCookie.add( "ACCESS_TOKEN=" + accessToken );
        accessTokenCookie.add( "Max-Age=" + ( 60 * 60 * 24 * 30 * 6 ) );
        accessTokenCookie.add( "Path=" + ACCESS_TOKEN_URI );
        accessTokenCookie.add( "HttpOnly=On" );
        accessTokenCookie.add( "Secure=On" );
        accessTokenCookie.add( "SameSite=" + ( origin != null && origin.contains( LOCAL_DOMAIN ) ? "None" : "Strict" ) );
        accessTokenCookie.add( "Domain=." + SecurityConfigurer.get().getCookieDomain() );

        StringJoiner refreshTokenCookie = new StringJoiner( "; " );
        refreshTokenCookie.add( "REFRESH_TOKEN=" + refreshToken );
        refreshTokenCookie.add( "Max-Age=" + ( 60 * 60 * 24 * 30 * 6 ) );
        refreshTokenCookie.add( "Path=" + REFRESH_TOKEN_URI );
        refreshTokenCookie.add( "HttpOnly=On" );
        refreshTokenCookie.add( "Secure=On" );
        refreshTokenCookie.add( "SameSite=" + ( origin != null && origin.contains( LOCAL_DOMAIN ) ? "None" : "Strict" ) );
        refreshTokenCookie.add( "Domain=." + SecurityConfigurer.get().getCookieDomain() );

        headers.add( "set-cookie", refreshTokenCookie.toString() );
        headers.add( "set-cookie", accessTokenCookie.toString() );

        return headers;
    }


    public static HttpHeaders setCookieToLogout( Request request ) {
        String origin = request.getHeader( "origin" );
        
        HttpHeaders headers = new HttpHeaders();

        StringJoiner accessTokenCookie = new StringJoiner( "; " );
        accessTokenCookie.add( "ACCESS_TOKEN=" );
        accessTokenCookie.add( "Max-Age=-1" );
        accessTokenCookie.add( "Path=" + ACCESS_TOKEN_URI );
        accessTokenCookie.add( "HttpOnly=On" );
        accessTokenCookie.add( "Secure=On" );
        accessTokenCookie.add( "SameSite=" + ( origin != null && origin.contains( LOCAL_DOMAIN ) ? "None" : "Strict" ) );
        accessTokenCookie.add( "Domain=." + SecurityConfigurer.get().getCookieDomain() );

        StringJoiner refreshTokenCookie = new StringJoiner( "; " );
        refreshTokenCookie.add( "REFRESH_TOKEN=" );
        refreshTokenCookie.add( "Max-Age=-1" );
        refreshTokenCookie.add( "Path=" + REFRESH_TOKEN_URI );
        refreshTokenCookie.add( "HttpOnly=On" );
        refreshTokenCookie.add( "Secure=On" );
        refreshTokenCookie.add( "SameSite=" + ( origin != null && origin.contains( LOCAL_DOMAIN ) ? "None" : "Strict" ) );
        refreshTokenCookie.add( "Domain=." + SecurityConfigurer.get().getCookieDomain() );

        headers.add( "set-cookie", refreshTokenCookie.toString() );
        headers.add( "set-cookie", accessTokenCookie.toString() );

        return headers;
    }

}
