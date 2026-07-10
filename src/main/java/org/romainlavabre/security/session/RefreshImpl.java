package org.romainlavabre.security.session;

import org.romainlavabre.dataconverter.Cast;
import org.romainlavabre.request.Request;
import org.romainlavabre.security.CognitoClaim;
import org.romainlavabre.security.CognitoToken;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class RefreshImpl implements Refresh {

    protected final CognitoGateway gateway;
    protected final JwtReader      jwtReader;
    protected final CookieBuilder  cookieBuilder;


    public RefreshImpl( CognitoGateway gateway, JwtReader jwtReader, CookieBuilder cookieBuilder ) {
        this.gateway       = gateway;
        this.jwtReader     = jwtReader;
        this.cookieBuilder = cookieBuilder;
    }


    @Override
    public RefreshResult refresh( Request request ) {
        SessionCookies session = SessionCookies.read( request );

        Map< String, Object > tokens = gateway.refreshAccessToken( session.clientId(), session.refreshToken() );

        String accessToken = tokens.get( CognitoToken.ACCESS_TOKEN ).toString();

        return new RefreshResult(
                List.of( cookieBuilder.accessToken( accessToken ) ),
                Cast.getLong( jwtReader.getBody( accessToken ).get( CognitoClaim.EXPIRE_AT ) )
        );
    }
}
