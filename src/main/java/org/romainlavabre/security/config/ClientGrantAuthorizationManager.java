package org.romainlavabre.security.config;

import jakarta.servlet.http.HttpServletRequest;
import org.romainlavabre.security.TokenClaims;
import org.romainlavabre.security.principal.PrincipalResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.Map;
import java.util.function.Supplier;

/**
 * What a client_credentials token is allowed to reach.
 * <p>
 * A CLIENT must prove two things its role alone does not say: that the token was minted for this
 * application, the aud claim, and that it was granted the read or the write of it, the scp (or scope)
 * claim, named {@code <prefix>:read} and {@code <prefix>:write}.
 * <p>
 * A USER is never concerned: its authorization is held entirely by its roles.
 * <p>
 * Composed with the role rule rather than replacing it, so that the matcher deciding which rule
 * applies stays the one the application declared.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class ClientGrantAuthorizationManager implements AuthorizationManager< RequestAuthorizationContext > {
    private static final Logger LOGGER = LoggerFactory.getLogger( "ClientGrant" );

    protected static final String READ  = ":read";
    protected static final String WRITE = ":write";

    protected static final AuthorizationDecision GRANTED = new AuthorizationDecision( true );
    protected static final AuthorizationDecision DENIED  = new AuthorizationDecision( false );

    protected final PrincipalResolver principalResolver;
    protected final String            audience;
    protected final String            scopePrefix;


    public ClientGrantAuthorizationManager( PrincipalResolver principalResolver, String audience, String scopePrefix ) {
        this.principalResolver = principalResolver;
        this.audience          = audience;
        this.scopePrefix       = scopePrefix;
    }


    @Override
    public AuthorizationResult authorize( Supplier< ? extends Authentication > authentication, RequestAuthorizationContext context ) {
        Authentication caller = authentication.get();

        // Http basic and any other non-JWT authentication carry no claim: the composed role rule decides for them
        if ( !( caller instanceof JwtAuthenticationToken jwtAuthentication ) ) {
            return GRANTED;
        }

        Jwt                   jwt    = jwtAuthentication.getToken();
        Map< String, Object > claims = jwt.getClaims();

        if ( !principalResolver.isClient( claims ) ) {
            return GRANTED;
        }

        if ( !TokenClaims.audiences( claims ).contains( audience ) ) {
            return deny( "audience", claims, context.getRequest() );
        }

        if ( !TokenClaims.hasScope( claims, expectedScope( context.getRequest() ) ) ) {
            return deny( "scope", claims, context.getRequest() );
        }

        return GRANTED;
    }


    /**
     * The HTTP method tells read from write. A write does not imply a read: a client granted the
     * write alone is refused on a GET.
     */
    protected String expectedScope( HttpServletRequest request ) {
        return scopePrefix + ( isRead( request ) ? READ : WRITE );
    }


    protected boolean isRead( HttpServletRequest request ) {
        String method = request.getMethod();

        return "GET".equalsIgnoreCase( method )
                || "HEAD".equalsIgnoreCase( method )
                || "OPTIONS".equalsIgnoreCase( method );
    }


    /**
     * The refusal is a bare 403 for the caller, this log is what tells a misprovisioned client from an
     * intrusion. It names the client, never the token.
     */
    protected AuthorizationResult deny( String missing, Map< String, Object > claims, HttpServletRequest request ) {
        LOGGER.warn(
                "Client denied: missing {}. client_id={} expected_audience={} received_audience={} expected_scope={} received_scope={} method={} uri={}",
                missing,
                claims.get( "client_id" ) != null ? claims.get( "client_id" ) : claims.get( "sub" ),
                audience,
                TokenClaims.audiences( claims ),
                expectedScope( request ),
                TokenClaims.scopes( claims ),
                request.getMethod(),
                request.getRequestURI()
        );

        return DENIED;
    }
}
