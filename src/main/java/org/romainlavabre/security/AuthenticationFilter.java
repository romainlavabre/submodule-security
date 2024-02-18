package org.romainlavabre.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
@Service
public class AuthenticationFilter extends GenericFilterBean {

    private static final String                BEARER = "Bearer";
    private final        JwtTokenHandler       jwtTokenHandler;
    private final        Security              security;
    @Autowired
    private              AuthenticationHandler authenticationHandler;


    public AuthenticationFilter(
            final JwtTokenHandler jwtTokenHandler,
            final Security security ) {
        this.jwtTokenHandler = jwtTokenHandler;
        this.security        = security;
    }


    @Override
    public void doFilter( final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain chain ) throws IOException, ServletException {

        final HttpServletRequest  request  = ( HttpServletRequest ) servletRequest;
        final HttpServletResponse response = ( HttpServletResponse ) servletResponse;

        final Optional< String > token = Optional.ofNullable( request.getHeader( HttpHeaders.AUTHORIZATION ) );

        final Authentication authentication;

        if ( token.isPresent() && token.get().startsWith( AuthenticationFilter.BEARER ) ) {

            final String bearerToken = token.get().substring( AuthenticationFilter.BEARER.length() + 1 );

            try {
                final Jws< Claims > claims = this.jwtTokenHandler.validateJwtToken( bearerToken );
                authentication = this.authenticationHandler.getAuthentication( claims );
                SecurityContextHolder.getContext().setAuthentication( authentication );
                this.hydrateSecurityService( claims );
            } catch ( final ExpiredJwtException exception ) {
                response.sendError( HttpServletResponse.SC_UNAUTHORIZED, "error.jwt.expired" );
                return;
            } catch ( final JwtException exception ) {
                response.sendError( HttpServletResponse.SC_UNAUTHORIZED, "error.jwt.invalid" );
                return;
            }

        }

        chain.doFilter( servletRequest, servletResponse );

        SecurityContextHolder.getContext().setAuthentication( null );
    }


    private void hydrateSecurityService( final Jws< Claims > claims ) {
        final SecurityImpl securityImpl = ( SecurityImpl ) this.security;

        securityImpl.hydrate(
                Long.parseLong( claims.getBody().getSubject() ),
                claims.getBody().get( "username" ).toString(),
                new HashSet<>( Arrays.asList( claims.getBody().get( "roles" ).toString().split( "," ) ) )
        );
    }

}
