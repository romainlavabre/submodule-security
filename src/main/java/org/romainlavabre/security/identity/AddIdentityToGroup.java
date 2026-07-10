package org.romainlavabre.security.identity;

/**
 * Adds an identity to an AWS Cognito group, as an administrator. The group drives the cognito:groups claim of
 * the tokens.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface AddIdentityToGroup {

    /**
     * @param username The username of the identity, not its sub.
     * @param group    The name of the group, it must already exist in the user pool.
     */
    void add( String username, String group );
}
