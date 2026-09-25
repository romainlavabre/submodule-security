package org.romainlavabre.security.principal;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authorization data of the caller.
 * <p>
 * Holds detached plain data only: no entity reference may escape a provider, so that a provider
 * reading a database can close its transaction before returning.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class Principal {

    public enum Type {
        USER,
        CLIENT
    }


    protected final String id;

    protected final Type type;

    protected final List< String > roles;

    protected final Map< String, Object > attributes;

    protected final String username;


    public Principal( String id, Type type, List< String > roles, Map< String, Object > attributes, String username ) {
        this.id         = id;
        this.type       = type;
        this.roles      = roles == null
                ? List.of()
                : Collections.unmodifiableList( new ArrayList<>( roles ) );
        this.attributes = attributes == null
                ? Map.of()
                : Collections.unmodifiableMap( new HashMap<>( attributes ) );
        this.username   = username;
    }


    /**
     * @return The sub for a USER, the client id for a CLIENT
     */
    public String getId() {
        return id;
    }


    public Type getType() {
        return type;
    }


    /**
     * @return Role names, ROLE_ prefixed, for both types
     */
    public List< String > getRoles() {
        return roles;
    }


    /**
     * @return Always empty for a CLIENT
     */
    public Map< String, Object > getAttributes() {
        return attributes;
    }


    /**
     * @return Always null for a CLIENT
     */
    public String getUsername() {
        return username;
    }


    public boolean isUser() {
        return type == Type.USER;
    }


    public boolean isClient() {
        return type == Type.CLIENT;
    }
}
