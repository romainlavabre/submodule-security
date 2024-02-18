package org.romainlavabre.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.romainlavabre.environment.Environment;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
@Service
public class JwtTokenImpl implements JwtTokenHandler {

    protected Environment    environment;
    protected UserRepository userRepository;


    public JwtTokenImpl(
            final Environment environment,
            final UserRepository userRepository ) {
        this.environment    = environment;
        this.userRepository = userRepository;
    }


    @Override
    public String createToken( final UserDetails userDetails ) {
        final User user = this.userRepository.findByUsername( userDetails.getUsername() );

        return Jwts.builder()
                .setExpiration( this.getExpiration() )
                .setIssuedAt( new Date() )
                .setSubject( String.valueOf( user.getId() ) )
                .claim( "username", user.getUsername() )
                .claim( "roles", String.join( ",", AuthorityUtils.authorityListToSet( userDetails.getAuthorities() ) ) )
                .signWith( Keys.hmacShaKeyFor( Base64.getDecoder().decode( SecurityConfigurer.get().getJwtSecret() ) ), SignatureAlgorithm.HS512 )
                .compact();
    }


    @Override
    public Jws< Claims > validateJwtToken( final String token ) {
        return Jwts.parser().setSigningKey( SecurityConfigurer.get().getJwtSecret() ).parseClaimsJws( token );
    }


    protected Date getExpiration() {
        final Calendar calendar = Calendar.getInstance();
        calendar.add( Calendar.SECOND, SecurityConfigurer.get().getJwtLifeTime() );

        return calendar.getTime();
    }
}
