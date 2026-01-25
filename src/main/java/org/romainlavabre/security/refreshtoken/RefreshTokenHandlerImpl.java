package org.romainlavabre.security.refreshtoken;

import org.romainlavabre.security.User;
import org.romainlavabre.tokengen.TokenGenerator;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.HexFormat;
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
                .setToken( hash( token ) )
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

        RefreshToken refreshToken = refreshTokenRepository.findByTokenAndDeviceId( hash( refreshTokenStr ), deviceId );

        if ( refreshToken == null ) {
            return null;
        }

        if ( refreshToken.getRotatedAt() != null && refreshToken.getRotatedAt().plusSeconds( TOLERANCE_SECONDS ).isBefore( ZonedDateTime.now( ZoneOffset.UTC ) ) ) {
            return null;
        }

        refreshToken.markAsUsed();

        return refreshToken.getUser();
    }


    protected String hash( String token ) {
        try {
            MessageDigest digest = MessageDigest.getInstance( "SHA-256" );
            byte[]        hash   = digest.digest( token.getBytes( StandardCharsets.UTF_8 ) );
            return HexFormat.of().formatHex( hash );
        } catch ( NoSuchAlgorithmException e ) {
            throw new IllegalStateException( "SHA-256 not available", e );
        }
    }
}
