package org.romainlavabre.security;

import java.util.ArrayList;
import java.util.List;

/**
 * Cognito groups carry no prefix convention, while Spring Security expects a ROLE_ prefixed authority
 * to answer hasRole().
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class RoleNormalizer {
    public static final String ROLE_PREFIX = "ROLE_";


    public static List< String > normalize( List< String > groups ) {
        List< String > roles = new ArrayList<>();

        if ( groups == null ) {
            return roles;
        }

        for ( String group : groups ) {
            roles.add( normalize( group ) );
        }

        return roles;
    }


    public static String normalize( String group ) {
        return group.startsWith( ROLE_PREFIX ) ? group : ROLE_PREFIX + group;
    }
}
