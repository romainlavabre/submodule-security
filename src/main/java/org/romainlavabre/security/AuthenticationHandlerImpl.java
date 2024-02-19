package org.romainlavabre.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.romainlavabre.request.Request;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.StringJoiner;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
@Service
public class AuthenticationHandlerImpl implements AuthenticationHandler {

    private final AuthenticationManager authenticationManager;


    public AuthenticationHandlerImpl( final AuthenticationManager authenticationManager ) {
        this.authenticationManager = authenticationManager;
    }


    @Override
    public Authentication getAuthentication( final Jws< Claims > token ) {
        StringJoiner stringJoiner = new StringJoiner( "," );

        for ( Object role : token.getBody().get( "roles", List.class ) ) {
            stringJoiner.add( role.toString() );
        }

        return new UsernamePasswordAuthenticationToken(
                token.getBody().get( "username" ),
                token,
                AuthorityUtils.commaSeparatedStringToAuthorityList( stringJoiner.toString() )
        );
    }


    @Override
    public Authentication authenticate( final Request request ) {

        final UsernamePasswordAuthenticationToken usernameAuthentication =
                new UsernamePasswordAuthenticationToken( request.getParameter( "auth_username" ), request.getParameter( "auth_password" ) );

        return this.authenticationManager.authenticate( usernameAuthentication );
    }
}
