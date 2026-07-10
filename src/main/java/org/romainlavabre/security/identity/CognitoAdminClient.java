package org.romainlavabre.security.identity;

import org.romainlavabre.security.config.SecurityConfigurer;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClientBuilder;

/**
 * Holds the client administrating the user pool. It is built on the first call, as the configuration is not
 * known yet when the bean is instantiated.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class CognitoAdminClient {

    private volatile CognitoIdentityProviderClient client;


    public CognitoIdentityProviderClient get() {
        if ( client == null ) {
            synchronized ( this ) {
                if ( client == null ) {
                    client = build();
                }
            }
        }

        return client;
    }


    public String getUserPoolId() {
        String userPoolId = SecurityConfigurer.get().getUserPoolId();

        if ( userPoolId == null || userPoolId.isBlank() ) {
            throw new IllegalStateException( "User pool id is required, use SecurityConfigurer.setUserPoolId()" );
        }

        return userPoolId;
    }


    protected CognitoIdentityProviderClient build() {
        SecurityConfigurer configurer = SecurityConfigurer.get();

        String region = configurer.getAwsRegion();

        if ( region == null || region.isBlank() ) {
            throw new IllegalStateException( "Aws region is required, use SecurityConfigurer.setAwsRegion()" );
        }

        CognitoIdentityProviderClientBuilder builder =
                CognitoIdentityProviderClient.builder()
                        .region( Region.of( region ) );

        String accessKey       = configurer.getAwsAccessKey();
        String secretAccessKey = configurer.getAwsSecretAccessKey();

        if ( accessKey == null || accessKey.isBlank() || secretAccessKey == null || secretAccessKey.isBlank() ) {
            return builder.credentialsProvider( DefaultCredentialsProvider.create() ).build();
        }

        return builder
                .credentialsProvider(
                        StaticCredentialsProvider.create( AwsBasicCredentials.create( accessKey, secretAccessKey ) )
                )
                .build();
    }
}
