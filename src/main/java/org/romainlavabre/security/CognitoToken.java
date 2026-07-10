package org.romainlavabre.security;

/**
 * Keys of the json body returned by the AWS Cognito /oauth2/token endpoint. They are not the ones of the
 * AuthenticationResult returned by the Cognito identity provider api.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface CognitoToken {
    String ACCESS_TOKEN = "access_token";
    String ID_TOKEN     = "id_token";

    /**
     * Absent from the response of the refresh token grant, Cognito does not rotate it.
     */
    String REFRESH_TOKEN = "refresh_token";

    String EXPIRES_IN = "expires_in";
}
