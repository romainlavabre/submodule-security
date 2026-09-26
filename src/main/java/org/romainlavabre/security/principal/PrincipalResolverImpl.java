package org.romainlavabre.security.principal;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class PrincipalResolverImpl implements PrincipalResolver {
    private static final Logger LOGGER = LoggerFactory.getLogger( "PrincipalResolver" );

    protected static final String CLAIM_SUB       = "sub";
    protected static final String CLAIM_AZP       = "azp";
    protected static final String CLAIM_CLIENT_ID = "client_id";

    protected static final String PREFIX_IDENTITY = "identity:";
    protected static final String PREFIX_CLIENT   = "client:";

    protected final PrincipalProvider principalProvider;

    private volatile Cache< String, Principal > cache;


    public PrincipalResolverImpl( PrincipalProvider principalProvider ) {
        this.principalProvider = principalProvider;
    }


    @Override
    public Principal resolve( Jwt jwt ) {
        return resolve( jwt.getClaims() );
    }


    @Override
    public Principal resolve( Map< String, Object > claims ) {
        String sub      = sub( claims );
        String clientId = clientId( claims );

        if ( isClient( claims ) ) {
            return orEmpty(
                    cache().get( PREFIX_CLIENT + clientId, key -> principalProvider.findClient( clientId ) ),
                    clientId,
                    Principal.Type.CLIENT
            );
        }

        return orEmpty(
                cache().get( PREFIX_IDENTITY + sub, key -> principalProvider.findIdentity( sub ) ),
                sub,
                Principal.Type.USER
        );
    }


    /**
     * A client_credentials token carries no user identity. Hydra reports it by setting the sub to the
     * client id, and a token without sub cannot stand for a user either.
     * <p>
     * A Kratos user token must therefore never carry a client_id or an azp equal to its sub, see
     * PrincipalResolverOryTokenShapeTest.
     */
    @Override
    public boolean isClient( Map< String, Object > claims ) {
        String sub = sub( claims );

        return sub == null
                || sub.isBlank()
                || sub.equals( clientId( claims ) );
    }


    @Override
    public void evictIdentity( String sub ) {
        cache().invalidate( PREFIX_IDENTITY + sub );
    }


    @Override
    public void evictClient( String clientId ) {
        cache().invalidate( PREFIX_CLIENT + clientId );
    }


    /**
     * Built on first use rather than in the constructor: the bean may be instantiated before the host
     * application has initialized its SecurityConfigurer.
     */
    protected Cache< String, Principal > cache() {
        if ( cache == null ) {
            synchronized ( this ) {
                if ( cache == null ) {
                    SecurityConfigurer securityConfigurer = SecurityConfigurer.get();

                    cache = Caffeine.newBuilder()
                            .maximumSize( securityConfigurer.getPrincipalCacheMaxSize() )
                            .expireAfterWrite( Duration.ofSeconds( securityConfigurer.getPrincipalCacheTtlSeconds() ) )
                            .recordStats()
                            .build();
                }
            }
        }

        return cache;
    }


    protected String sub( Map< String, Object > claims ) {
        return asString( claims.get( CLAIM_SUB ) );
    }


    protected String clientId( Map< String, Object > claims ) {
        return asString( claims.get( CLAIM_AZP ) != null ? claims.get( CLAIM_AZP ) : claims.get( CLAIM_CLIENT_ID ) );
    }


    /**
     * An unknown id denies rather than fails: a deleted identity must not answer 500 on every call.
     * The warning is what makes a misconfigured provider, where nothing resolves, diagnosable.
     */
    protected Principal orEmpty( Principal principal, String id, Principal.Type type ) {
        if ( principal != null ) {
            return principal;
        }

        LOGGER.warn( "No {} found for id {}, resolving without any role", type, id );

        return new Principal( id, type, List.of(), Map.of(), null );
    }


    protected String asString( Object value ) {
        return value == null ? null : value.toString();
    }
}
