package org.romainlavabre.security.config;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import org.romainlavabre.security.BearerTokenExtractor;
import org.romainlavabre.security.CognitoClaim;
import org.romainlavabre.security.RoleNormalizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

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

    private final ObjectMapper objectMapper = new ObjectMapper();


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

                    for ( Map.Entry< String, String > entry : SecurityConfigurer.get().getSecuredEndpoints().entrySet() ) {
                        String role = new SecurityRole( entry.getValue() ).toString();

                        if ( entry.getKey().startsWith( "REG:" ) ) {
                            auth.requestMatchers( RegexRequestMatcher.regexMatcher( entry.getKey().replaceFirst( "REG:", "" ) ) )
                                    .hasRole( role );
                        } else {
                            auth.requestMatchers( entry.getKey() ).hasRole( role );
                        }
                    }

                    auth.anyRequest().authenticated();
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
     * Each issuer owns its decoder, the right one is picked from the iss claim of the incoming token.
     * When no jwks uri is provided, the issuer well-known configuration is fetched at startup.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        Map< String, String > issuers = SecurityConfigurer.get().getIssuers();

        if ( issuers.isEmpty() ) {
            throw new IllegalStateException( "At least one issuer is required, use SecurityConfigurer.addIssuer()" );
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

        return token -> {
            String issuer = extractIssuer( token );

            JwtDecoder decoder = decoders.get( issuer );

            if ( decoder == null ) {
                throw new JwtException( "Unknown issuer: " + issuer );
            }

            return decoder.decode( token );
        };
    }


    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter( jwt ->
                RoleNormalizer.normalize( jwt.getClaimAsStringList( CognitoClaim.GROUPS ) )
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
                getAccessTokenValidator(),
                getClientIdValidator()
        );
    }


    /**
     * An id token carries the same groups than an access token, but it is not an authorization token.
     */
    protected OAuth2TokenValidator< Jwt > getAccessTokenValidator() {
        return jwt -> CognitoClaim.ACCESS_TOKEN_USE.equals( jwt.getClaimAsString( CognitoClaim.TOKEN_USE ) )
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure( new OAuth2Error( INVALID_TOKEN_CODE, "Only an access token is accepted", null ) );
    }


    /**
     * A Cognito access token carries no aud claim, client_id stands for it.
     */
    protected OAuth2TokenValidator< Jwt > getClientIdValidator() {
        List< String > allowedClientIds = SecurityConfigurer.get().getAllowedClientIds();

        return jwt -> allowedClientIds.isEmpty() || allowedClientIds.contains( jwt.getClaimAsString( CognitoClaim.CLIENT_ID ) )
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure( new OAuth2Error( INVALID_TOKEN_CODE, "Unknown client id", null ) );
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


    private String extractIssuer( String token ) {
        try {
            String[] parts = token.split( "\\." );

            JsonNode payload = objectMapper.readTree( new String( Base64.getUrlDecoder().decode( parts[ 1 ] ) ) );

            return payload.get( "iss" ).asString();
        } catch ( Exception e ) {
            throw new JwtException( "Invalid JWT", e );
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
