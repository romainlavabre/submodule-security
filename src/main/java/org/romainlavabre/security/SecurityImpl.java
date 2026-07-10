package org.romainlavabre.security;

import org.romainlavabre.request.Request;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.web.context.annotation.RequestScope;

import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
@Service
@RequestScope
public class SecurityImpl implements Security {

    protected Map< String, Object > body;
    protected Collection< String >  roles;


    public SecurityImpl( Request request, JwtDecoder jwtDecoder ) {
        this.body  = null;
        this.roles = List.of();

        final String token = BearerTokenExtractor.extract( request.getHeader( HttpHeaders.AUTHORIZATION ), request.getCookies() );

        if ( token == null || token.isBlank() ) {
            return;
        }

        final Jwt jwt;

        try {
            jwt = jwtDecoder.decode( token );
        } catch ( final JwtException exception ) {
            return;
        }

        this.body  = jwt.getClaims();
        this.roles = RoleNormalizer.normalize( jwt.getClaimAsStringList( CognitoClaim.GROUPS ) );
    }


    @Override
    public long getId() {
        if ( hasAttribute( "external_id" ) ) {
            return Long.parseLong( getAttribute( "external_id" ).toString() );
        }

        return -1;
    }


    @Override
    public String getAuthenticationId() {
        return this.body.get( CognitoClaim.SUBJECT ).toString();
    }


    @Override
    public String getUsername() {
        final Object username = this.body.get( CognitoClaim.USERNAME );

        return username != null ? username.toString() : null;
    }


    @Override
    public Collection< String > getRoles() {
        return this.roles;
    }


    @Override
    public boolean hasRole( final String role ) {
        return this.roles.contains( RoleNormalizer.normalize( role ) );
    }


    @Override
    @Deprecated
    public boolean hasUserConnected() {
        return hasConnected();
    }


    @Override
    public boolean hasConnected() {
        return this.body != null;
    }


    @Override
    public boolean hasUser() {
        return getUsername() != null;
    }


    @Override
    public boolean hasClient() {
        return getUsername() == null;
    }


    @Override
    public String[] getScopes() {
        final Object scope = this.body.get( CognitoClaim.SCOPE );

        if ( scope == null ) {
            return new String[ 0 ];
        }

        return scope.toString().split( " " );
    }


    @Override
    public boolean hasScope( final String scope ) {
        for ( final String localScope : getScopes() ) {
            if ( localScope.equalsIgnoreCase( scope ) ) {
                return true;
            }
        }

        return false;
    }


    @Override
    public String getClientId() {
        final Object clientId = this.body.get( CognitoClaim.CLIENT_ID );

        return clientId != null ? clientId.toString() : null;
    }


    @Override
    public boolean hasAttribute( final String attribute ) {
        return getAttribute( attribute ) != null;
    }


    /**
     * Reads an attribute either from the "attributes" claim, injected by a pre token generation lambda,
     * or from the native Cognito custom attributes.
     */
    @Override
    public Object getAttribute( final String attribute ) {
        if ( this.body == null ) {
            return null;
        }

        final Object attributes = this.body.get( CognitoClaim.ATTRIBUTES );

        if ( attributes instanceof Map< ?, ? > map && map.get( attribute ) != null ) {
            return map.get( attribute );
        }

        return this.body.get( CognitoClaim.CUSTOM_ATTRIBUTE_PREFIX + attribute );
    }


    @Override
    public boolean has( final String claim ) {
        return this.body.containsKey( claim );
    }


    @Override
    public Object get( final String claim ) {
        return this.body.get( claim );
    }
}
