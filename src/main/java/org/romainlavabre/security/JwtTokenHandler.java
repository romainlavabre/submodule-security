package org.romainlavabre.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
public interface JwtTokenHandler {


    String createToken( UserDetails user );


    String createToken( User user );


    Jws< Claims > validateJwtToken( String token );
}
