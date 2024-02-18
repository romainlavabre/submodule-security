package org.romainlavabre.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.romainlavabre.environment.Environment;
import org.romainlavabre.security.attribute.ClaimBuilder;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
@Service
public class JwtTokenImpl implements JwtTokenHandler {

    protected final Environment          environment;
    protected final UserRepository       userRepository;
    protected final List< ClaimBuilder > claimBuilders;


    public JwtTokenImpl(
            Environment environment,
            UserRepository userRepository,
            List< ClaimBuilder > claimBuilders ) {
        this.environment    = environment;
        this.userRepository = userRepository;
        this.claimBuilders  = claimBuilders;
    }


    @Override
    public String createToken( final UserDetails userDetails ) {
        final User user = this.userRepository.findByUsername( userDetails.getUsername() );

        JwtBuilder jwtBuilder = Jwts.builder()
                .setExpiration( this.getExpiration() )
                .setIssuedAt( new Date() )
                .setSubject( String.valueOf( user.getId() ) );

        for ( ClaimBuilder claimBuilder : claimBuilders ) {
            jwtBuilder.claim( claimBuilder.name(), claimBuilder.value( user ) );
        }

        return jwtBuilder.signWith( Keys.hmacShaKeyFor( Base64.getDecoder().decode( SecurityConfigurer.get().getJwtSecret() ) ), SignatureAlgorithm.HS512 )
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
