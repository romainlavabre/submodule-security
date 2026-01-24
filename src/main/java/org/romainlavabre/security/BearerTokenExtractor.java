package org.romainlavabre.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.romainlavabre.security.config.SecurityConfigurer;

import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class BearerTokenExtractor {
    public static final String ACCESS_TOKEN_COOKIE_NAME = "ACCESS_TOKEN";


    public static String extract( String authorizationHeader, Cookie[] cookies ) {
        if ( cookies != null ) {
            for ( Cookie cookie : cookies ) {
                if ( ACCESS_TOKEN_COOKIE_NAME.equals( cookie.getName() ) ) {
                    return cookie.getValue();
                }
            }
        }

        if ( authorizationHeader != null && !authorizationHeader.isBlank() && authorizationHeader.contains( "Bearer" ) ) {
            return authorizationHeader.replace( "Bearer", "" ).trim();
        }


        return null;
    }


    public static boolean isJwtRequired( HttpServletRequest request ) {
        if ( request.getRequestURI().contains( "/userinfo" ) ) {
            return true;
        }

        for ( Map.Entry< String, String > entry : SecurityConfigurer.get().getSecuredEndpoints().entrySet() ) {
            if ( entry.getKey().startsWith( "REG:" ) ) {
                if ( request.getRequestURI().matches( entry.getKey().replaceFirst( "REG:", "" ) ) ) {
                    return true;
                }
            }

            if ( request.getRequestURI().startsWith( entry.getKey().replace( "/**", "" ) ) ) {
                return true;
            }

        }

        return false;
    }
}
