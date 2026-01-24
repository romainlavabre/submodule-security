package org.romainlavabre.security.refreshtoken;

import org.romainlavabre.security.User;
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


    public RefreshTokenHandlerImpl( RefreshTokenRepository refreshTokenRepository ) {
        this.refreshTokenRepository = refreshTokenRepository;
    }


    @Override
    public String generateRefreshToken( User user ) {
        List< RefreshToken > refreshTokens = refreshTokenRepository.findAllByUser( user );

        for ( RefreshToken refreshToken : refreshTokens ) {
            if ( refreshToken.getRotatedAt() != null && refreshToken.getRotatedAt().plusSeconds( TOLERANCE_SECONDS ).isBefore( ZonedDateTime.now( ZoneOffset.UTC ) ) ) {
                refreshTokenRepository.delete( refreshToken );
            }
        }

        RefreshToken current = refreshTokenRepository.findByUserAndRotatedAtIsNull( user );

        if ( current == null ) {
            RefreshToken refreshToken = new RefreshToken();
            refreshToken.setUser( user );

            refreshTokenRepository.save( refreshToken );

            return refreshToken.getToken();
        }

        return current.getToken();
    }


    @Override
    public User reauth( String refreshTokenStr ) {
        if ( refreshTokenStr == null ) {
            return null;
        }

        RefreshToken refreshToken = refreshTokenRepository.findByToken( refreshTokenStr );

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
