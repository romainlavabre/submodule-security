package org.romainlavabre.security.identity;

import org.romainlavabre.security.ory.Page;

import java.util.Map;
import java.util.Optional;

/**
 * Administrates the Kratos identities, through its admin API. The meaning of metadata_admin belongs to
 * the application: this interface reads and writes it as an opaque map.
 * <p>
 * Every id is checked before being put in a URL: an unsafe one is refused with a 400.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface KratosIdentities {

    /**
     * @param pageSize  1 to 1000
     * @param pageToken Token of the page to read, null for the first one
     * @param email     Exact login identifier to filter on, null for all
     */
    Page< KratosIdentity > list( int pageSize, String pageToken, String email );


    /**
     * @return Empty when Kratos does not know this id
     */
    Optional< KratosIdentity > find( String id );


    /**
     * @return Empty when no identity logs in with this email
     */
    Optional< KratosIdentity > findByEmail( String email );


    /**
     * Replaces the whole metadata_admin of the identity.
     */
    void replaceMetadataAdmin( String id, Map< String, Object > metadataAdmin );


    /**
     * Changes the login email of the identity, marked verified as on creation. 409 when another identity
     * already logs in with it.
     */
    void updateEmail( String id, String email );


    /**
     * An inactive identity can no longer log in. Its running sessions are not revoked: see
     * revokeSessions.
     */
    void setActive( String id, boolean active );


    /**
     * Best-effort: an already absent identity is not an error.
     */
    void delete( String id );


    /**
     * Revokes every session of the identity: its refresh fails at once, its access token lives until
     * its own expiry. An identity without session is not an error.
     */
    void revokeSessions( String id );
}
