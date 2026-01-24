package org.romainlavabre.security.controller;

import jakarta.transaction.Transactional;
import org.romainlavabre.encoder.Encoder;
import org.romainlavabre.request.Request;
import org.romainlavabre.security.*;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.romainlavabre.security.cookie.CookieBuilder;
import org.romainlavabre.security.refreshtoken.RefreshTokenHandler;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@RestController( "SecurityController" )
public class SecurityController {

    protected final JwtTokenHandler       jwtTokenHandler;
    protected final AuthenticationHandler authenticationHandler;
    protected final UserDetailsService    userDetailsService;
    protected final Security              security;
    protected final UserRepository        userRepository;
    protected final RefreshTokenHandler   refreshTokenHandler;
    protected final Request               request;


    public SecurityController(
            JwtTokenHandler jwtTokenHandler,
            AuthenticationHandler authenticationHandler,
            @Qualifier( "userDetailsService" ) UserDetailsService userDetailsService,
            Security security,
            UserRepository userRepository,
            RefreshTokenHandler refreshTokenHandler,
            Request request ) {
        this.jwtTokenHandler       = jwtTokenHandler;
        this.authenticationHandler = authenticationHandler;
        this.userDetailsService    = userDetailsService;
        this.security              = security;
        this.userRepository        = userRepository;
        this.refreshTokenHandler   = refreshTokenHandler;
        this.request               = request;
    }


    @GetMapping( path = "/userinfo" )
    public ResponseEntity< Map< String, Object > > userInfo() {
        return ResponseEntity.ok( Encoder.encode( userRepository.findByUsername( this.security.getUsername() ) ) );
    }


    @Transactional
    @PostMapping( path = "/auth/token" )
    public ResponseEntity< Object > authenticate( @CookieValue( name = "DEVICE_ID", required = false ) String deviceId ) {

        Authentication authentication = null;
        String         message        = null;

        try {
            authentication = this.authenticationHandler.authenticate( this.request );
        } catch ( final Throwable e ) {
            e.printStackTrace();
            message = e.getMessage();
        }

        if ( authentication != null && authentication.isAuthenticated() ) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername( ( String ) this.request.getParameter( "auth_username" ) );

            if ( !userDetails.isEnabled() ) {
                return ResponseEntity.status( HttpStatus.UNAUTHORIZED ).body( Map.of( "message", "UNAUTHORIZED" ) );
            }

            String accessToken  = this.jwtTokenHandler.createToken( userDetails );
            String refreshToken = refreshTokenHandler.generateRefreshToken( userRepository.findByUsername( userDetails.getUsername() ), deviceId );

            HttpHeaders httpHeaders = CookieBuilder.setCookieToLogin( request, accessToken, refreshToken );

            return ResponseEntity
                    .ok()
                    .headers( httpHeaders )
                    .body( Map.of(
                            "access_token", accessToken,
                            "token_type", "Bearer",
                            "expires_in", SecurityConfigurer.get().getJwtLifeTime(),
                            "refresh_token", refreshToken
                    ) );
        }

        if ( message == null ) {
            message = "UNAUTHORIZED";
        }

        return ResponseEntity.status( HttpStatus.UNAUTHORIZED ).body( Map.of( "message", message ) );
    }


    @Transactional
    @PostMapping( path = "/auth/refresh" )
    public ResponseEntity< Object > refresh( @CookieValue( name = "REFRESH_TOKEN", required = false ) String refreshToken, @CookieValue( name = "DEVICE_ID", required = false ) String deviceId ) {
        User user = refreshTokenHandler.reauth( refreshToken, deviceId );

        if ( user == null ) {
            return ResponseEntity.status( HttpStatus.UNAUTHORIZED ).body( Map.of( "message", "INVALID_REFRESH_TOKEN" ) );
        }

        String accessToken     = this.jwtTokenHandler.createToken( user );
        String newRefreshToken = refreshTokenHandler.generateRefreshToken( user, deviceId );

        HttpHeaders httpHeaders = CookieBuilder.setCookieToLogin( request, accessToken, newRefreshToken );

        return ResponseEntity
                .ok()
                .headers( httpHeaders )
                .body( Map.of(
                        "access_token", accessToken,
                        "token_type", "Bearer",
                        "expires_in", SecurityConfigurer.get().getJwtLifeTime(),
                        "refresh_token", newRefreshToken
                ) );
    }


    @Transactional
    @PostMapping( path = "/auth/revoke" )
    public ResponseEntity< Object > revoke() {
        HttpHeaders httpHeaders = CookieBuilder.setCookieToLogout( request );

        return ResponseEntity.noContent().headers( httpHeaders ).build();
    }


}
