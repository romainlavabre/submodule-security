package org.romainlavabre.security.refreshtoken;

import org.romainlavabre.security.User;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface RefreshTokenHandler {

    String generateRefreshToken( User user, String deviceId );


    User reauth( String refreshToken, String deviceId );
}
