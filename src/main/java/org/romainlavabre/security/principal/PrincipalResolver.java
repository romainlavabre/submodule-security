package org.romainlavabre.security.principal;

import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Map;

/**
 * Resolves the caller's authorization data from the claims natively carried by the token.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface PrincipalResolver {

    Principal resolve( Jwt jwt );


    /**
     * @param claims The decoded token body, for callers holding no Jwt instance
     */
    Principal resolve( Map< String, Object > claims );


    /**
     * Tells a client_credentials token from a user one. Getting this wrong hands the roles of a
     * client to a user, or the other way around.
     */
    boolean isClient( Map< String, Object > claims );
}
