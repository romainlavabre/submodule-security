package org.romainlavabre.security.identity;

import org.romainlavabre.exception.HttpBadRequestException;
import org.romainlavabre.exception.HttpConflictException;
import org.romainlavabre.exception.HttpInternalServerErrorException;
import org.romainlavabre.rest.Response;
import org.romainlavabre.rest.Rest;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.romainlavabre.security.message.Error;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class CreateIdentityImpl implements CreateIdentity {
    protected static final int CONFLICT = 409;

    protected static final String SCHEMA_ID = "default";


    @Override
    public String create( String email ) {
        if ( email == null || email.isBlank() ) {
            throw new HttpBadRequestException( Error.IDP_USERNAME_REQUIRED, false );
        }

        String address = email.trim();

        Response response =
                Rest.builder()
                        .post( KratosAdmin.url() + "/admin/identities" )
                        .jsonBody( Map.of(
                                "schema_id", SCHEMA_ID,
                                "traits", Map.of( "email", address ),
                                // The address is the one the application registered: no verification mail
                                "verifiable_addresses", List.of( Map.of(
                                        "value", address,
                                        "via", "email",
                                        "verified", true,
                                        "status", "completed"
                                ) )
                        ) )
                        .buildAndSend();

        if ( response.status() == CONFLICT ) {
            throw new HttpConflictException( Error.IDP_IDENTITY_ALREADY_EXISTS, false );
        }

        if ( !response.isSuccess() || response.getBodyAsMap().get( "id" ) == null ) {
            throw new HttpInternalServerErrorException( Error.IDP_IDENTITY_CREATION_FAILED, false );
        }

        return response.getBodyAsMap().get( "id" ).toString();
    }
}
