package org.romainlavabre.security.hydra;

import org.romainlavabre.exception.HttpBadRequestException;
import org.romainlavabre.exception.HttpInternalServerErrorException;
import org.romainlavabre.rest.Response;
import org.romainlavabre.rest.Rest;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.romainlavabre.security.message.Error;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class HydraClientsImpl implements HydraClients {
    protected static final int SECRET_BYTES = 32;

    protected final SecureRandom secureRandom = new SecureRandom();


    @Override
    public Credentials create( String name, List< String > scopes, List< String > audiences ) {
        Map< String, Object > payload = new HashMap<>();
        payload.put( "client_name", name );
        payload.put( "grant_types", List.of( "client_credentials" ) );
        // client_id and client_secret sent in the form body, not in a Basic Auth header
        payload.put( "token_endpoint_auth_method", "client_secret_post" );
        // Hydra carries the scope as a single space separated string, and the audience as an array
        payload.put( "scope", String.join( " ", scopes ) );
        payload.put( "audience", audiences );

        Response response =
                Rest.builder()
                        .post( adminUrl() + "/admin/clients" )
                        .jsonBody( payload )
                        .buildAndSend();

        if ( !response.isSuccess() ) {
            throw new HttpInternalServerErrorException( Error.IDP_HYDRA_CLIENT_FAILED, false );
        }

        Object clientId     = response.getBodyAsMap().get( "client_id" );
        Object clientSecret = response.getBodyAsMap().get( "client_secret" );

        if ( clientId == null || clientSecret == null ) {
            throw new HttpInternalServerErrorException( Error.IDP_HYDRA_CLIENT_FAILED, false );
        }

        return new Credentials( clientId.toString(), clientSecret.toString() );
    }


    @Override
    public String rotateSecret( String clientId ) {
        assertClientId( clientId );

        String secret = newSecret();

        Response response =
                Rest.builder()
                        .patch( adminUrl() + "/admin/clients/" + clientId )
                        .jsonBody( List.of(
                                Map.of( "op", "replace", "path", "/client_secret", "value", secret )
                        ) )
                        .buildAndSend();

        if ( !response.isSuccess() ) {
            throw new HttpInternalServerErrorException( Error.IDP_HYDRA_CLIENT_FAILED, false );
        }

        return secret;
    }


    /**
     * The application is the source of truth: a client already missing in Hydra (404) must not block
     * the local revocation.
     */
    @Override
    public void delete( String clientId ) {
        assertClientId( clientId );

        Rest.builder()
                .delete( adminUrl() + "/admin/clients/" + clientId )
                .buildAndSend();
    }


    protected String newSecret() {
        byte[] bytes = new byte[ SECRET_BYTES ];

        secureRandom.nextBytes( bytes );

        return HexFormat.of().formatHex( bytes );
    }


    protected void assertClientId( String clientId ) {
        if ( clientId == null || clientId.isBlank() ) {
            throw new HttpBadRequestException( Error.IDP_CLIENT_ID_REQUIRED, false );
        }
    }


    protected String adminUrl() {
        String url = SecurityConfigurer.get().getHydraAdminUrl();

        if ( url == null || url.isBlank() ) {
            throw new IllegalStateException( "Hydra admin url is required, use SecurityConfigurer.setHydraAdminUrl()" );
        }

        return url;
    }
}
