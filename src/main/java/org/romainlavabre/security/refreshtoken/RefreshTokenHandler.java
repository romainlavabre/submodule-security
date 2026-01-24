package org.romainlavabre.security.refreshtoken;

import org.romainlavabre.security.User;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface RefreshTokenHandler {

    String generateRefreshToken( User user );


    User reauth( String refreshToken );
}
