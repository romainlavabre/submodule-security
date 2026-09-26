package org.romainlavabre.security.hydra;

import org.romainlavabre.exception.HttpInternalServerErrorException;
import org.romainlavabre.rest.RequestBuilder;
import org.romainlavabre.rest.Response;
import org.romainlavabre.rest.Rest;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.romainlavabre.security.message.Error;
import org.romainlavabre.security.ory.LinkHeader;
import org.romainlavabre.security.ory.OryId;
import org.romainlavabre.security.ory.OryJson;
import org.romainlavabre.security.ory.Page;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.*;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class HydraClientsImpl implements HydraClients {
    protected static final int SECRET_BYTES = 32;
    protected static final int NOT_FOUND    = 404;

    protected static final int MIN_PAGE_SIZE = 1;
    protected static final int MAX_PAGE_SIZE = 500;

    protected final SecureRandom secureRandom = new SecureRandom();


    @Override
    public Credentials create( String name, List< String > scopes, List< String > audiences ) {
        return create( name, scopes, audiences, null );
    }


    @Override
    public Credentials create( String name, List< String > scopes, List< String > audiences, Map< String, Object > metadata ) {
        Map< String, Object > payload = new HashMap<>();
        payload.put( "client_name", name );
        payload.put( "grant_types", List.of( "client_credentials" ) );
        // client_id and client_secret sent in the form body, not in a Basic Auth header
        payload.put( "token_endpoint_auth_method", "client_secret_post" );
        // Hydra carries the scope as a single space separated string, and the audience as an array
        payload.put( "scope", String.join( " ", scopes ) );
        payload.put( "audience", audiences );

        if ( metadata != null && !metadata.isEmpty() ) {
            payload.put( "metadata", metadata );
        }

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
    public Page< HydraClient > list( int pageSize, String pageToken, String name ) {
        RequestBuilder request =
                Rest.builder()
                        .get( adminUrl() + "/admin/clients" )
                        .queryString( "page_size", String.valueOf( Math.clamp( pageSize, MIN_PAGE_SIZE, MAX_PAGE_SIZE ) ) );

        if ( pageToken != null && !pageToken.isBlank() ) {
            request.queryString( "page_token", pageToken );
        }

        if ( name != null && !name.isBlank() ) {
            request.queryString( "client_name", name.trim() );
        }

        Response response = request.buildAndSend();

        assertSuccess( response );

        List< HydraClient > clients = new ArrayList<>();

        for ( Object client : response.getBodyAsList() ) {
            clients.add( toClient( OryJson.map( client ) ) );
        }

        return new Page<>( clients, LinkHeader.nextPageToken( response ) );
    }


    @Override
    public Optional< HydraClient > find( String clientId ) {
        assertClientId( clientId );

        Response response =
                Rest.builder()
                        .get( adminUrl() + "/admin/clients/" + clientId )
                        .buildAndSend();

        if ( response.status() == NOT_FOUND ) {
            return Optional.empty();
        }

        assertSuccess( response );

        return Optional.of( toClient( response.getBodyAsMap() ) );
    }


    @Override
    public void updateScopes( String clientId, List< String > scopes ) {
        patch( clientId, "/scope", String.join( " ", scopes ) );
    }


    @Override
    public void updateAudiences( String clientId, List< String > audiences ) {
        patch( clientId, "/audience", audiences );
    }


    @Override
    public void replaceMetadata( String clientId, Map< String, Object > metadata ) {
        patch( clientId, "/metadata", metadata != null ? metadata : Map.of() );
    }


    @Override
    public String rotateSecret( String clientId ) {
        String secret = newSecret();

        patch( clientId, "/client_secret", secret );

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


    /**
     * add rather than replace: JSON Patch refuses to replace a member that does not exist, and Hydra
     * may omit the metadata until it is first set.
     */
    protected void patch( String clientId, String path, Object value ) {
        assertClientId( clientId );

        Response response =
                Rest.builder()
                        .patch( adminUrl() + "/admin/clients/" + clientId )
                        .jsonBody( List.of( Map.of( "op", "add", "path", path, "value", value ) ) )
                        .buildAndSend();

        assertSuccess( response );
    }


    protected HydraClient toClient( Map< String, Object > client ) {
        String scope = OryJson.string( client.get( "scope" ) );

        return new HydraClient(
                OryJson.string( client.get( "client_id" ) ),
                OryJson.string( client.get( "client_name" ) ),
                scope == null || scope.isBlank() ? List.of() : List.of( scope.trim().split( "\\s+" ) ),
                OryJson.strings( client.get( "audience" ) ),
                OryJson.map( client.get( "metadata" ) ),
                OryJson.string( client.get( "created_at" ) )
        );
    }


    protected String newSecret() {
        byte[] bytes = new byte[ SECRET_BYTES ];

        secureRandom.nextBytes( bytes );

        return HexFormat.of().formatHex( bytes );
    }


    protected void assertClientId( String clientId ) {
        OryId.assertSafe( clientId, Error.IDP_CLIENT_ID_REQUIRED, Error.IDP_CLIENT_ID_INVALID );
    }


    protected void assertSuccess( Response response ) {
        if ( !response.isSuccess() ) {
            throw new HttpInternalServerErrorException( Error.IDP_HYDRA_CLIENT_FAILED, false );
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
