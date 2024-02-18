package org.romainlavabre.security.config;

import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
@Configuration
@EnableWebSecurity
public class Security {
    private static final String TOKEN_ROLE_CLAIM = "roles";


    @Bean
    public SecurityFilterChain filterChain( final HttpSecurity http ) throws Exception {
        String[] publicE = new String[ SecurityConfigurer.get().getPublicEndpoint().size() ];

        AuthorizeHttpRequestsConfigurer< HttpSecurity >.AuthorizationManagerRequestMatcherRegistry a =
                http
                        .cors().and().csrf().disable()
                        .sessionManagement().sessionCreationPolicy( SessionCreationPolicy.STATELESS )
                        .and()
                        .anonymous()
                        .and()
                        .authorizeHttpRequests()
                        .dispatcherTypeMatchers( DispatcherType.ERROR ).permitAll()
                        .requestMatchers( HttpMethod.OPTIONS ).permitAll()
                        .requestMatchers( SecurityConfigurer.get().getPublicEndpoint().toArray( publicE ) ).permitAll();

        for ( Map.Entry< String, String > entry : SecurityConfigurer.get().getSecuredEndpoints().entrySet() ) {
            if ( entry.getKey().startsWith( "REG:" ) ) {
                a.requestMatchers( request -> request.getRequestURI().matches( entry.getKey().replaceFirst( "REG:", "" ) ) ).hasRole( new SecurityRole( entry.getValue() ).toString() );
            } else {

                a.requestMatchers( entry.getKey() ).hasRole( new SecurityRole( entry.getValue() ).toString() );
            }
        }

        a.anyRequest().authenticated();

        if ( !SecurityConfigurer.get().getInMemoryUsers().isEmpty() ) {
            a.and().httpBasic();
        }

        return a.and().build();
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins( List.of( "*" ) );
        configuration.setAllowedMethods( List.of( "HEAD",
                "GET", "POST", "PUT", "DELETE", "PATCH" ) );
        configuration.setAllowCredentials( false );
        configuration.setAllowedHeaders( List.of( "Authorization", "Cache-Control", "Content-Type" ) );

        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration( "/**", configuration );
        return source;
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


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public AuthenticationManager authenticationManager( AuthenticationConfiguration config ) throws Exception {
        return config.getAuthenticationManager();
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
