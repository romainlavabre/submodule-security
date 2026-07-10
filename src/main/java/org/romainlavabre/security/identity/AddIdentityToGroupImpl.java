package org.romainlavabre.security.identity;

import org.romainlavabre.exception.HttpBadRequestException;
import org.romainlavabre.exception.HttpInternalServerErrorException;
import org.romainlavabre.exception.HttpNotFoundException;
import org.romainlavabre.security.message.Error;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminAddUserToGroupRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.CognitoIdentityProviderException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.ResourceNotFoundException;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class AddIdentityToGroupImpl implements AddIdentityToGroup {

    private static final Logger LOGGER = LoggerFactory.getLogger( AddIdentityToGroupImpl.class );

    protected final CognitoAdminClient cognitoAdminClient;


    public AddIdentityToGroupImpl( CognitoAdminClient cognitoAdminClient ) {
        this.cognitoAdminClient = cognitoAdminClient;
    }


    @Override
    public void add( String username, String group ) {
        if ( username == null || username.isBlank() ) {
            throw new HttpBadRequestException( Error.IDP_USERNAME_REQUIRED, false );
        }

        if ( group == null || group.isBlank() ) {
            throw new HttpBadRequestException( Error.IDP_GROUP_REQUIRED, false );
        }

        try {
            cognitoAdminClient.get().adminAddUserToGroup(
                    AdminAddUserToGroupRequest.builder()
                            .userPoolId( cognitoAdminClient.getUserPoolId() )
                            .username( username.trim() )
                            .groupName( group )
                            .build()
            );
        } catch ( ResourceNotFoundException e ) {
            throw new HttpNotFoundException( Error.IDP_GROUP_NOT_FOUND, false );
        } catch ( CognitoIdentityProviderException e ) {
            LOGGER.error(
                    "adminAddUserToGroup failed for username={} group={}: {} - {}",
                    username.trim(),
                    group,
                    e.getClass().getSimpleName(),
                    e.awsErrorDetails() != null ? e.awsErrorDetails().errorMessage() : e.getMessage()
            );

            throw new HttpInternalServerErrorException( Error.IDP_ADD_TO_GROUP_FAILED, false );
        }
    }
}
