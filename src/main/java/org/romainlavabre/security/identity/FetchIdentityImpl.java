package org.romainlavabre.security.identity;

import kong.unirest.core.json.JSONObject;
import org.romainlavabre.exception.HttpBadRequestException;
import org.romainlavabre.exception.HttpInternalServerErrorException;
import org.romainlavabre.rest.Response;
import org.romainlavabre.rest.Rest;
import org.romainlavabre.security.message.Error;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class FetchIdentityImpl implements FetchIdentity {

    @Override
    public String fetchSubByEmail( String email ) {
        if ( email == null || email.isBlank() ) {
            throw new HttpBadRequestException( Error.IDP_USERNAME_REQUIRED, false );
        }

        Response response =
                Rest.builder()
                        .get( KratosAdmin.url() + "/admin/identities" )
                        .queryString( "credentials_identifier", email.trim() )
                        .buildAndSend();

        if ( !response.isSuccess() ) {
            throw new HttpInternalServerErrorException( Error.IDP_FETCH_FAILED, false );
        }

        List< Object > identities = response.getBodyAsList();

        if ( identities.isEmpty() ) {
            return null;
        }

        Object id = toMap( identities.get( 0 ) ).get( "id" );

        return id != null ? id.toString() : null;
    }


    /**
     * getBodyAsList hands back the JSON type of the underlying HTTP library (kong.unirest), not a Map:
     * testing only for a Map would silently lose the identity.
     */
    protected Map< ?, ? > toMap( Object identity ) {
        if ( identity instanceof JSONObject jsonObject ) {
            return jsonObject.toMap();
        }

        if ( identity instanceof Map< ?, ? > map ) {
            return map;
        }

        throw new HttpInternalServerErrorException( Error.IDP_FETCH_FAILED, false );
    }
}
