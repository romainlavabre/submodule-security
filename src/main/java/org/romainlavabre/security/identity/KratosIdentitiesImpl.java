package org.romainlavabre.security.identity;

import org.romainlavabre.exception.HttpBadRequestException;
import org.romainlavabre.exception.HttpInternalServerErrorException;
import org.romainlavabre.rest.Response;
import org.romainlavabre.rest.RequestBuilder;
import org.romainlavabre.rest.Rest;
import org.romainlavabre.security.message.Error;
import org.romainlavabre.security.ory.LinkHeader;
import org.romainlavabre.security.ory.OryId;
import org.romainlavabre.security.ory.OryJson;
import org.romainlavabre.security.ory.Page;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class KratosIdentitiesImpl implements KratosIdentities {
    protected static final int NOT_FOUND = 404;

    protected static final int MIN_PAGE_SIZE = 1;
    protected static final int MAX_PAGE_SIZE = 1000;


    @Override
    public Page< KratosIdentity > list( int pageSize, String pageToken, String email ) {
        RequestBuilder request =
                Rest.builder()
                        .get( KratosAdmin.url() + "/admin/identities" )
                        .queryString( "page_size", String.valueOf( Math.clamp( pageSize, MIN_PAGE_SIZE, MAX_PAGE_SIZE ) ) );

        if ( pageToken != null && !pageToken.isBlank() ) {
            request.queryString( "page_token", pageToken );
        }

        if ( email != null && !email.isBlank() ) {
            request.queryString( "credentials_identifier", email.trim() );
        }

        Response response = request.buildAndSend();

        assertSuccess( response );

        List< KratosIdentity > identities = new ArrayList<>();

        for ( Object identity : response.getBodyAsList() ) {
            identities.add( toIdentity( OryJson.map( identity ) ) );
        }

        return new Page<>( identities, LinkHeader.nextPageToken( response ) );
    }


    @Override
    public Optional< KratosIdentity > find( String id ) {
        assertId( id );

        Response response =
                Rest.builder()
                        .get( KratosAdmin.url() + "/admin/identities/" + id )
                        .buildAndSend();

        if ( response.status() == NOT_FOUND ) {
            return Optional.empty();
        }

        assertSuccess( response );

        return Optional.of( toIdentity( response.getBodyAsMap() ) );
    }


    @Override
    public Optional< KratosIdentity > findByEmail( String email ) {
        if ( email == null || email.isBlank() ) {
            throw new HttpBadRequestException( Error.IDP_USERNAME_REQUIRED, false );
        }

        List< KratosIdentity > identities = list( MIN_PAGE_SIZE, null, email ).items();

        return identities.isEmpty() ? Optional.empty() : Optional.of( identities.get( 0 ) );
    }


    /**
     * add rather than replace: JSON Patch refuses to replace a member that does not exist, and Kratos
     * omits metadata_admin until it is first set.
     */
    @Override
    public void replaceMetadataAdmin( String id, Map< String, Object > metadataAdmin ) {
        patch( id, "/metadata_admin", metadataAdmin != null ? metadataAdmin : Map.of() );
    }


    @Override
    public void setActive( String id, boolean active ) {
        patch( id, "/state", active ? KratosIdentity.STATE_ACTIVE : KratosIdentity.STATE_INACTIVE );
    }


    @Override
    public void delete( String id ) {
        assertId( id );

        Response response =
                Rest.builder()
                        .delete( KratosAdmin.url() + "/admin/identities/" + id )
                        .buildAndSend();

        if ( response.status() != NOT_FOUND ) {
            assertSuccess( response );
        }
    }


    @Override
    public void revokeSessions( String id ) {
        assertId( id );

        Response response =
                Rest.builder()
                        .delete( KratosAdmin.url() + "/admin/identities/" + id + "/sessions" )
                        .buildAndSend();

        if ( response.status() != NOT_FOUND ) {
            assertSuccess( response );
        }
    }


    protected void patch( String id, String path, Object value ) {
        assertId( id );

        Response response =
                Rest.builder()
                        .patch( KratosAdmin.url() + "/admin/identities/" + id )
                        .jsonBody( List.of( Map.of( "op", "add", "path", path, "value", value ) ) )
                        .buildAndSend();

        assertSuccess( response );
    }


    protected KratosIdentity toIdentity( Map< String, Object > identity ) {
        return new KratosIdentity(
                OryJson.string( identity.get( "id" ) ),
                OryJson.string( OryJson.map( identity.get( "traits" ) ).get( "email" ) ),
                OryJson.string( identity.get( "state" ) ),
                OryJson.map( identity.get( "metadata_admin" ) ),
                OryJson.string( identity.get( "created_at" ) ),
                OryJson.string( identity.get( "updated_at" ) )
        );
    }


    protected void assertId( String id ) {
        OryId.assertSafe( id, Error.IDP_IDENTITY_ID_REQUIRED, Error.IDP_IDENTITY_ID_INVALID );
    }


    protected void assertSuccess( Response response ) {
        if ( !response.isSuccess() ) {
            throw new HttpInternalServerErrorException( Error.IDP_IDENTITY_FAILED, false );
        }
    }
}
