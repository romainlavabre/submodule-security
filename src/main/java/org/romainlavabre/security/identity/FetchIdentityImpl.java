package org.romainlavabre.security.identity;

import org.romainlavabre.exception.HttpBadRequestException;
import org.romainlavabre.exception.HttpInternalServerErrorException;
import org.romainlavabre.security.CognitoAttribute;
import org.romainlavabre.security.message.Error;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class FetchIdentityImpl implements FetchIdentity {

    protected final CognitoAdminClient cognitoAdminClient;


    public FetchIdentityImpl( CognitoAdminClient cognitoAdminClient ) {
        this.cognitoAdminClient = cognitoAdminClient;
    }


    @Override
    public String fetchSubByEmail( String email ) {
        if ( email == null || email.isBlank() ) {
            throw new HttpBadRequestException( Error.IDP_USERNAME_REQUIRED, false );
        }

        AdminGetUserResponse response;

        try {
            response = cognitoAdminClient.get().adminGetUser(
                    AdminGetUserRequest.builder()
                            .userPoolId( cognitoAdminClient.getUserPoolId() )
                            .username( email.trim() )
                            .build()
            );
        } catch ( UserNotFoundException e ) {
            return null;
        } catch ( CognitoIdentityProviderException e ) {
            throw new HttpInternalServerErrorException( Error.IDP_FETCH_FAILED, false );
        }

        return response.userAttributes()
                .stream()
                .filter( attribute -> CognitoAttribute.SUB.equals( attribute.name() ) )
                .findFirst()
                .map( AttributeType::value )
                .orElse( null );
    }
}
