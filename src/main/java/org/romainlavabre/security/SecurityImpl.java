package org.romainlavabre.security;

import org.romainlavabre.request.Request;
import org.romainlavabre.security.principal.Principal;
import org.romainlavabre.security.principal.PrincipalResolver;
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
    protected static final String CLAIM_SUB       = "sub";
    protected static final String CLAIM_AZP       = "azp";
    protected static final String CLAIM_CLIENT_ID = "client_id";

    protected Map< String, Object > body;
    protected Principal             principal;


    public SecurityImpl( Request request, PrincipalResolver principalResolver, JwtDecoder jwtDecoder ) {
        this.body      = null;
        this.principal = null;

        /*
         * Same predicate as the BearerTokenResolver, so that this never claims to know a caller
         * Spring Security did not authenticate: on a public endpoint it resolves no token, hence no
         * identity here either. Both fields must stay null together, everything below hasConnected()
         * reads one of them.
         */
        if ( !BearerTokenExtractor.isJwtRequired( request.getUri() ) ) {
            return;
        }

        final String token = BearerTokenExtractor.extract( request.getHeader( HttpHeaders.AUTHORIZATION ), request.getCookies() );

        if ( token == null || token.isBlank() ) {
            return;
        }

        final Jwt jwt;

        /*
         * A token the decoder rejects is not an identity, and must not fail the request either.
         * Denying access where an identity is required is the filter chain's job.
         */
        try {
            jwt = jwtDecoder.decode( token );
        } catch ( final JwtException exception ) {
            return;
        }

        this.body      = jwt.getClaims();
        this.principal = principalResolver.resolve( this.body );
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
        return this.body.get( CLAIM_SUB ).toString();
    }


    /**
     * Everything reading the principal answers as an unidentified caller rather than throwing, so
     * that a caller forgetting to guard with {@link #hasConnected()} denies instead of returning a 500.
     */
    @Override
    public String getUsername() {
        return this.principal != null ? this.principal.getUsername() : null;
    }


    @Override
    public Collection< String > getRoles() {
        return this.principal != null ? this.principal.getRoles() : List.of();
    }


    @Override
    public boolean hasRole( final String role ) {
        return getRoles().contains( role );
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
        return this.principal != null && this.principal.isUser();
    }


    @Override
    public boolean hasClient() {
        return this.principal != null && this.principal.isClient();
    }


    /**
     * Reads {@code scp} as well as {@code scope}: Hydra emits the first as an array.
     */
    @Override
    public String[] getScopes() {
        return TokenClaims.scopes( this.body ).toArray( new String[ 0 ] );
    }


    @Override
    public boolean hasScope( final String scope ) {
        return TokenClaims.hasScope( this.body, scope );
    }


    @Override
    public String getClientId() {
        if ( this.body == null ) {
            return null;
        }

        final Object clientId = this.body.get( CLAIM_AZP ) != null ? this.body.get( CLAIM_AZP ) : this.body.get( CLAIM_CLIENT_ID );

        return clientId != null ? clientId.toString() : null;
    }


    @Override
    public boolean hasAttribute( final String attribute ) {
        return this.principal != null && this.principal.getAttributes().get( attribute ) != null;
    }


    /**
     * Attributes come from the PrincipalProvider of the application, never from the token.
     */
    @Override
    public Object getAttribute( final String attribute ) {
        return this.principal != null ? this.principal.getAttributes().get( attribute ) : null;
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
