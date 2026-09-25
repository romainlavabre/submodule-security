package org.romainlavabre.security.session;

import org.romainlavabre.request.Request;
import org.romainlavabre.rest.Rest;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Revokes the Kratos session (public logout API, by session token) and clears the cookies. Idempotent:
 * a missing or already revoked session still clears them.
 * <p>
 * An access token already handed out stays valid until its expiry, which is the TTL of the tokenizer.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class LogoutImpl implements Logout {

    protected final CookieBuilder cookieBuilder;


    public LogoutImpl( CookieBuilder cookieBuilder ) {
        this.cookieBuilder = cookieBuilder;
    }


    @Override
    public List< String > logout( Request request ) {
        String sessionToken = SessionCookies.readSessionToken( request );

        if ( sessionToken != null ) {
            Rest.builder()
                    .delete( SecurityConfigurer.get().getKratosPublicUrl() + "/self-service/logout/api" )
                    .jsonBody( Map.of( "session_token", sessionToken ) )
                    .buildAndSend();
        }

        return List.of(
                cookieBuilder.accessToken( null ),
                cookieBuilder.refreshToken( null )
        );
    }
}
