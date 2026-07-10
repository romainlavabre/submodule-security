package org.romainlavabre.security.session;

import org.romainlavabre.dataconverter.Cast;
import org.romainlavabre.exception.HttpBadRequestException;
import org.romainlavabre.request.Request;
import org.romainlavabre.security.CognitoClaim;
import org.romainlavabre.security.CognitoToken;
import org.romainlavabre.security.message.Error;
import org.romainlavabre.security.parameter.AuthParameter;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class ExchangeCodeImpl implements ExchangeCode {

    protected final CognitoGateway gateway;
    protected final JwtReader      jwtReader;
    protected final CookieBuilder  cookieBuilder;


    public ExchangeCodeImpl( CognitoGateway gateway, JwtReader jwtReader, CookieBuilder cookieBuilder ) {
        this.gateway       = gateway;
        this.jwtReader     = jwtReader;
        this.cookieBuilder = cookieBuilder;
    }


    @Override
    public ExchangeResult exchange( Request request ) {
        String clientId    = request.getParameter( AuthParameter.CLIENT_ID, String.class );
        String redirectUri = request.getParameter( AuthParameter.REDIRECT_URI, String.class );
        String code        = request.getParameter( AuthParameter.CODE, String.class );

        assertProvided( clientId, Error.IDP_CLIENT_ID_REQUIRED );
        assertProvided( redirectUri, Error.IDP_REDIRECT_URI_REQUIRED );
        assertProvided( code, Error.IDP_CODE_REQUIRED );

        Map< String, Object > tokens = gateway.exchangeAuthorizationCode( clientId, redirectUri, code );

        String accessToken  = tokens.get( CognitoToken.ACCESS_TOKEN ).toString();
        String refreshToken = tokens.get( CognitoToken.REFRESH_TOKEN ).toString();

        return new ExchangeResult(
                List.of(
                        cookieBuilder.accessToken( accessToken ),
                        cookieBuilder.refreshToken( refreshToken ),
                        cookieBuilder.clientId( clientId )
                ),
                Cast.getLong( jwtReader.getBody( accessToken ).get( CognitoClaim.EXPIRE_AT ) )
        );
    }


    protected void assertProvided( String value, String error ) {
        if ( value == null || value.isBlank() ) {
            throw new HttpBadRequestException( error, false );
        }
    }
}
