package org.romainlavabre.security;

/**
 * Claims of an AWS Cognito access token.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface CognitoClaim {
    String SUBJECT   = "sub";
    String GROUPS    = "cognito:groups";
    String USERNAME  = "username";
    String CLIENT_ID = "client_id";
    String SCOPE     = "scope";
    String TOKEN_USE = "token_use";
    String EXPIRE_AT = "exp";

    /**
     * Set by a pre token generation lambda, when the token is enriched with data owned by the application.
     */
    String ATTRIBUTES = "attributes";

    /**
     * Prefix of the native Cognito custom attributes.
     */
    String CUSTOM_ATTRIBUTE_PREFIX = "custom:";

    String ACCESS_TOKEN_USE = "access";
}
