package org.romainlavabre.security.refreshtoken;

import org.romainlavabre.security.PasswordEncoder;
import org.romainlavabre.security.User;
import org.romainlavabre.tokengen.TokenGenerator;
import org.springframework.stereotype.Service;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class RefreshTokenHandlerImpl implements RefreshTokenHandler {
    private static final long TOLERANCE_SECONDS = 30;

    protected final RefreshTokenRepository refreshTokenRepository;
    protected final PasswordEncoder        passwordEncoder;


    public RefreshTokenHandlerImpl( RefreshTokenRepository refreshTokenRepository, PasswordEncoder passwordEncoder ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordEncoder        = passwordEncoder;
    }


    @Override
    public String generateRefreshToken( User user, String deviceId ) {
        List< RefreshToken > refreshTokens = refreshTokenRepository.findAllByUserAndDeviceId( user, deviceId );

        for ( RefreshToken refreshToken : refreshTokens ) {
            if ( refreshToken.getRotatedAt() != null && refreshToken.getRotatedAt().plusSeconds( TOLERANCE_SECONDS ).isBefore( ZonedDateTime.now( ZoneOffset.UTC ) ) ) {
                refreshTokenRepository.delete( refreshToken );
            }
        }

        RefreshToken current = refreshTokenRepository.findByUserAndRotatedAtIsNullAndDeviceId( user, deviceId );

        String token = TokenGenerator.generateSecureCode( 64 );

        RefreshToken refreshToken = new RefreshToken();
        refreshToken
                .setUser( user )
                .setToken( passwordEncoder.encode( token ) )
                .setDeviceId( deviceId );

        refreshTokenRepository.save( refreshToken );

        if ( current != null ) {
            current.markAsUsed();
        }

        return token;
    }


    @Override
    public User reauth( String refreshTokenStr, String deviceId ) {
        if ( refreshTokenStr == null ) {
            return null;
        }

        RefreshToken refreshToken = refreshTokenRepository.findByTokenAndDeviceId( passwordEncoder.encode( refreshTokenStr ), deviceId );

        if ( refreshToken == null ) {
            return null;
        }

        if ( refreshToken.getRotatedAt() != null && refreshToken.getRotatedAt().plusSeconds( TOLERANCE_SECONDS ).isBefore( ZonedDateTime.now( ZoneOffset.UTC ) ) ) {
            return null;
        }

        refreshToken.markAsUsed();

        return refreshToken.getUser();
    }
}
