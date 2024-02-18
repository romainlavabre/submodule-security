package org.romainlavabre.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.romainlavabre.request.Request;
import org.springframework.security.core.Authentication;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
public interface AuthenticationHandler {
    Authentication getAuthentication( Jws< Claims > token );


    Authentication authenticate( final Request request );
}
