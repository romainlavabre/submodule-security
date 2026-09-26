package org.romainlavabre.security.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import org.romainlavabre.security.BearerTokenExtractor;
import org.romainlavabre.security.TokenClaims;
import org.romainlavabre.security.principal.PrincipalResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.text.ParseException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
@Configuration
@EnableWebSecurity
public class Security {
    private static final String SESSION_ENDPOINTS  = "/auth/**";
    private static final String INVALID_TOKEN_CODE = "invalid_token";

    protected final PrincipalResolver principalResolver;
    private final   ObjectMapper      objectMapper = new ObjectMapper();


    public Security( PrincipalResolver principalResolver ) {
        this.principalResolver = principalResolver;
    }


    @Bean
    public SecurityFilterChain filterChain( final HttpSecurity http ) throws Exception {
        String[] publicEndpoints = SecurityConfigurer.get()
                .getPublicEndpoint()
                .toArray( new String[ 0 ] );

        http
                .csrf( csrf -> csrf.disable() )
                .sessionManagement( session -> session.sessionCreationPolicy( SessionCreationPolicy.STATELESS ) )
                .authorizeHttpRequests( auth -> {
                    auth.dispatcherTypeMatchers( DispatcherType.ERROR ).permitAll();
                    auth.requestMatchers( HttpMethod.OPTIONS ).permitAll();
                    auth.requestMatchers( SESSION_ENDPOINTS ).permitAll();

                    if ( publicEndpoints.length > 0 ) {
                        auth.requestMatchers( publicEndpoints ).permitAll();
                    }

                    ClientGrantAuthorizationManager clientGrant = clientGrantAuthorizationManager();

                    for ( Map.Entry< String, String > entry : SecurityConfigurer.get().getSecuredEndpoints().entrySet() ) {
                        String role = new SecurityRole( entry.getValue() ).toString();

                        AuthorizeHttpRequestsConfigurer< HttpSecurity >.AuthorizedUrl url = entry.getKey().startsWith( "REG:" )
                                ? auth.requestMatchers( RegexRequestMatcher.regexMatcher( entry.getKey().replaceFirst( "REG:", "" ) ) )
                                : auth.requestMatchers( entry.getKey() );

                        if ( clientGrant == null ) {
                            url.hasRole( role );
                        } else {
                            url.access( AuthorizationManagers.allOf(
                                    AuthorityAuthorizationManager.< RequestAuthorizationContext >hasRole( role ),
                                    clientGrant
                            ) );
                        }
                    }

                    if ( clientGrant == null ) {
                        auth.anyRequest().authenticated();
                    } else {
                        auth.anyRequest().access( AuthorizationManagers.allOf(
                                AuthenticatedAuthorizationManager.< RequestAuthorizationContext >authenticated(),
                                clientGrant
                        ) );
                    }
                } )
                .oauth2ResourceServer( oauth2 ->
                        oauth2
                                .jwt( jwt ->
                                        jwt
                                                .jwtAuthenticationConverter( jwtAuthenticationConverter() )
                                                .decoder( jwtDecoder() )
                                )
                                .bearerTokenResolver( getBearerTokenResolver() )
                );

        if ( !SecurityConfigurer.get().getInMemoryUsers().isEmpty() ) {
            http.httpBasic( basic -> {
            } );
        }

        return http.build();
    }


    /**
     * @return Null when the application did not call requireClientScopes(): the roles alone decide
     */
    protected ClientGrantAuthorizationManager clientGrantAuthorizationManager() {
        SecurityConfigurer securityConfigurer = SecurityConfigurer.get();

        if ( !securityConfigurer.isClientScopesRequired() ) {
            return null;
        }

        return new ClientGrantAuthorizationManager(
                principalResolver,
                securityConfigurer.getAudience(),
                securityConfigurer.getClientScopePrefix()
        );
    }


    /**
     * Each issuer owns its decoder, the right one is picked from the iss claim of the incoming token.
     * An issuer registered with addIssuer() fetches its keys over HTTP (Hydra), one registered with
     * addIssuerWithJwks() is checked against the keys it was given (Kratos tokenizer).
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        Map< String, String > issuers         = SecurityConfigurer.get().getIssuers();
        Map< String, String > issuersWithJwks = SecurityConfigurer.get().getIssuersWithJwks();

        if ( issuers.isEmpty() && issuersWithJwks.isEmpty() ) {
            throw new IllegalStateException( "At least one issuer is required, use SecurityConfigurer.addIssuer() or addIssuerWithJwks()" );
        }

        Map< String, JwtDecoder > decoders = new HashMap<>();

        for ( Map.Entry< String, String > entry : issuers.entrySet() ) {
            String issuer  = entry.getKey();
            String jwksUri = entry.getValue();

            NimbusJwtDecoder decoder = jwksUri != null && !jwksUri.isBlank()
                    ? NimbusJwtDecoder.withJwkSetUri( jwksUri ).build()
                    : JwtDecoders.fromIssuerLocation( issuer );

            decoder.setJwtValidator( getJwtValidator( issuer ) );

            decoders.put( issuer, decoder );
        }

        for ( Map.Entry< String, String > entry : issuersWithJwks.entrySet() ) {
            NimbusJwtDecoder decoder = staticJwksDecoder( entry.getKey(), entry.getValue() );

            decoder.setJwtValidator( getJwtValidator( entry.getKey() ) );

            decoders.put( entry.getKey(), decoder );
        }

        return token -> {
            String issuer = extractIssuer( token );

            JwtDecoder decoder = decoders.get( issuer );

            if ( decoder == null ) {
                throw new BadJwtException( "Unknown issuer: " + issuer );
            }

            return decoder.decode( token );
        };
    }


    /**
     * Roles come from the application, through the PrincipalResolver: the identity provider carries none.
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter( jwt ->
                principalResolver.resolve( jwt )
                        .getRoles()
                        .stream()
                        .map( role -> ( GrantedAuthority ) new SimpleGrantedAuthority( role ) )
                        .toList()
        );

        return jwtAuthenticationConverter;
    }


    @Bean
    public UserDetailsService users() {
        List< InMemoryUser > inMemoryUsers = SecurityConfigurer.get().getInMemoryUsers();

        UserDetails[] userDetails = new UserDetails[ inMemoryUsers.size() ];

        for ( int i = 0; i < inMemoryUsers.size(); i++ ) {
            userDetails[ i ] = inMemoryUsers.get( i ).toUserDetails();
        }

        return new InMemoryUserDetailsManager( userDetails );
    }


    protected OAuth2TokenValidator< Jwt > getJwtValidator( String issuer ) {
        return new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer( issuer ),
                getAudienceValidator()
        );
    }


    /**
     * A token minted for another audience must not open this one, even when signed by a trusted issuer.
     * Without a configured audience every token passes, which only suits an application with a single
     * audience per issuer.
     */
    protected OAuth2TokenValidator< Jwt > getAudienceValidator() {
        return jwt -> {
            String audience = SecurityConfigurer.get().getAudience();

            if ( audience == null || audience.isBlank() || TokenClaims.audiences( jwt.getClaims() ).contains( audience ) ) {
                return OAuth2TokenValidatorResult.success();
            }

            return OAuth2TokenValidatorResult.failure( new OAuth2Error( INVALID_TOKEN_CODE, "The token is not issued for this audience", null ) );
        };
    }


    /**
     * The accepted algorithms are those the keys declare, RS256 when none does.
     */
    protected NimbusJwtDecoder staticJwksDecoder( String issuer, String jwksJson ) {
        JWKSet jwkSet;

        try {
            jwkSet = JWKSet.parse( jwksJson );
        } catch ( ParseException | RuntimeException e ) {
            throw new IllegalStateException( "Invalid json web key set for issuer " + issuer, e );
        }

        if ( jwkSet.getKeys().isEmpty() ) {
            throw new IllegalStateException( "The json web key set of issuer " + issuer + " holds no key" );
        }

        for ( JWK jwk : jwkSet.getKeys() ) {
            if ( jwk.isPrivate() ) {
                throw new IllegalStateException( "The json web key set of issuer " + issuer + " holds a private key, only the public one is expected" );
            }
        }

        NimbusJwtDecoder.JwkSourceJwtDecoderBuilder builder = NimbusJwtDecoder.withJwkSource( new ImmutableJWKSet<>( jwkSet ) );

        for ( JWK jwk : jwkSet.getKeys() ) {
            if ( jwk.getAlgorithm() != null ) {
                builder.jwsAlgorithm( SignatureAlgorithm.from( jwk.getAlgorithm().getName() ) );
            }
        }

        return builder.build();
    }


    protected BearerTokenResolver getBearerTokenResolver() {
        return new BearerTokenResolver() {
            @Override
            public String resolve( HttpServletRequest request ) {
                if ( BearerTokenExtractor.isJwtRequired( request ) ) {
                    return BearerTokenExtractor.extract( request.getHeader( "Authorization" ), request.getCookies() );
                }

                return null;
            }
        };
    }


    /**
     * BadJwtException, not JwtException: JwtAuthenticationProvider turns the first into a 401 and the
     * second into a 500. A caller sending a malformed bearer is unauthenticated, not a server fault.
     */
    private String extractIssuer( String token ) {
        try {
            String[] parts = token.split( "\\." );

            JsonNode payload = objectMapper.readTree( new String( Base64.getUrlDecoder().decode( parts[ 1 ] ) ) );

            return payload.get( "iss" ).asString();
        } catch ( Exception e ) {
            throw new BadJwtException( "Invalid JWT", e );
        }
    }


    private class SecurityRole {
        private final String ROLE;


        public SecurityRole( String role ) {
            ROLE = role;
        }


        @Override
        public String toString() {
            return ROLE.replace( "ROLE_", "" );
        }
    }
}
