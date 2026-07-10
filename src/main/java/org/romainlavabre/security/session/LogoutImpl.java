package org.romainlavabre.security.session;

import org.romainlavabre.request.Request;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class LogoutImpl implements Logout {

    protected final CognitoGateway gateway;
    protected final CookieBuilder  cookieBuilder;


    public LogoutImpl( CognitoGateway gateway, CookieBuilder cookieBuilder ) {
        this.gateway       = gateway;
        this.cookieBuilder = cookieBuilder;
    }


    @Override
    public List< String > logout( Request request ) {
        SessionCookies session = SessionCookies.read( request );

        gateway.revokeRefreshToken( session.clientId(), session.refreshToken() );

        return List.of(
                cookieBuilder.accessToken( null ),
                cookieBuilder.refreshToken( null ),
                cookieBuilder.clientId( null )
        );
    }
}
