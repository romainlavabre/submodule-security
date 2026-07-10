package org.romainlavabre.security.session;

import org.romainlavabre.exception.HttpInternalServerErrorException;
import org.romainlavabre.exception.HttpNotFoundException;
import org.romainlavabre.rest.RequestBuilder;
import org.romainlavabre.rest.Response;
import org.romainlavabre.rest.Rest;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.romainlavabre.security.message.Error;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Talks to the AWS Cognito oauth2 endpoints as a confidential client. The client secret never leaves the server.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class CognitoGateway {
    private static final String TOKEN_URI  = "/oauth2/token";
    private static final String REVOKE_URI = "/oauth2/revoke";


    public Map< String, Object > exchangeAuthorizationCode( String clientId, String redirectUri, String code ) {
        Response response =
                Rest.builder()
                        .post( getUrl( TOKEN_URI ) )
                        .field( "grant_type", "authorization_code" )
                        .field( "client_id", clientId )
                        .field( "client_secret", getClientSecret( clientId ) )
                        .field( "redirect_uri", redirectUri )
                        .field( "code", code )
                        .buildAndSend( RequestBuilder.RESPONSE_JSON );

        if ( !response.isSuccess() ) {
            throw new HttpInternalServerErrorException( Error.IDP_EXCHANGE_CODE_FAILED, false );
        }

        return response.getBodyAsMap();
    }


    /**
     * Cognito does not rotate the refresh token on this grant, only a new access token is returned.
     */
    public Map< String, Object > refreshAccessToken( String clientId, String refreshToken ) {
        Response response =
                Rest.builder()
                        .post( getUrl( TOKEN_URI ) )
                        .field( "grant_type", "refresh_token" )
                        .field( "client_id", clientId )
                        .field( "client_secret", getClientSecret( clientId ) )
                        .field( "refresh_token", refreshToken )
                        .buildAndSend( RequestBuilder.RESPONSE_JSON );

        if ( !response.isSuccess() ) {
            throw new HttpInternalServerErrorException( Error.IDP_REFRESH_FAILED, false );
        }

        return response.getBodyAsMap();
    }


    public void revokeRefreshToken( String clientId, String refreshToken ) {
        Response response =
                Rest.builder()
                        .post( getUrl( REVOKE_URI ) )
                        .withBasicAuth( clientId, getClientSecret( clientId ) )
                        .field( "token", refreshToken )
                        .buildAndSend( RequestBuilder.RESPONSE_JSON );

        if ( !response.isSuccess() ) {
            throw new HttpInternalServerErrorException( Error.IDP_REVOKE_FAILED, false );
        }
    }


    protected String getClientSecret( String clientId ) {
        String clientSecret = SecurityConfigurer.get().getClientSecret( clientId );

        if ( clientSecret == null || clientSecret.isBlank() ) {
            throw new HttpNotFoundException( Error.IDP_CLIENT_NOT_FOUND, false );
        }

        return clientSecret;
    }


    protected String getUrl( String uri ) {
        String url = SecurityConfigurer.get().getCognitoUrl();

        if ( url == null || url.isBlank() ) {
            throw new IllegalStateException( "Cognito url is required, use SecurityConfigurer.setCognitoUrl()" );
        }

        return url + uri;
    }
}
