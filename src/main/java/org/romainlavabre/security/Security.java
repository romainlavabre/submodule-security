package org.romainlavabre.security;

import java.util.Collection;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
public interface Security {

    /**
     * @return Value of the principal attribute external_id, -1 if not provided by the PrincipalProvider
     */
    long getId();


    String getAuthenticationId();


    String getUsername();


    Collection< String > getRoles();


    boolean hasRole( String role );


    @Deprecated
    boolean hasUserConnected();


    boolean hasConnected();


    boolean hasUser();


    boolean hasClient();


    String[] getScopes();


    boolean hasScope( String scope );


    String getClientId();


    boolean hasAttribute( String attribute );


    Object getAttribute( String attribute );


    boolean has( String claim );


    Object get( String claim );
}
