package org.romainlavabre.security.controller;

import org.romainlavabre.request.Request;
import org.romainlavabre.security.Security;
import org.romainlavabre.security.session.Login;
import org.romainlavabre.security.session.Logout;
import org.romainlavabre.security.session.Refresh;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@RestController( "SecurityController" )
public class SecurityController {

    protected final Login    login;
    protected final Refresh  refresh;
    protected final Logout   logout;
    protected final Security security;
    protected final Request  request;


    public SecurityController(
            Login login,
            Refresh refresh,
            Logout logout,
            Security security,
            Request request ) {
        this.login    = login;
        this.refresh  = refresh;
        this.logout   = logout;
        this.security = security;
        this.request  = request;
    }


    /**
     * Same answer whether the identifier exists or not, throttled or not.
     */
    @PostMapping( path = "/auth/login" )
    public ResponseEntity< Void > login() {
        Login.InitResult result = login.init( request );

        return ResponseEntity
                .noContent()
                .headers( toHeaders( result.getCookies() ) )
                .build();
    }


    @PostMapping( path = "/auth/login/verify" )
    public ResponseEntity< Map< String, Object > > verify() {
        Login.VerifyResult result = login.verify( request );

        return ResponseEntity
                .ok()
                .headers( toHeaders( result.getCookies() ) )
                .body( Map.of( "exp", result.getExp() ) );
    }


    @PostMapping( path = "/auth/refresh" )
    public ResponseEntity< Map< String, Object > > refresh() {
        Refresh.RefreshResult result = this.refresh.refresh( request );

        return ResponseEntity
                .ok()
                .headers( toHeaders( result.getCookies() ) )
                .body( Map.of( "exp", result.getExp() ) );
    }


    @PostMapping( path = "/auth/logout" )
    public ResponseEntity< Void > logout() {
        List< String > cookies = logout.logout( request );

        return ResponseEntity
                .noContent()
                .headers( toHeaders( cookies ) )
                .build();
    }


    /**
     * Fed by the Principal the application resolved, not by the token.
     */
    @GetMapping( path = "/userinfo" )
    public ResponseEntity< Map< String, Object > > userInfo() {
        Map< String, Object > body = new HashMap<>();

        body.put( "sub", security.getAuthenticationId() );
        body.put( "username", security.getUsername() );
        body.put( "roles", security.getRoles() );
        body.put( "scopes", security.getScopes() );

        return ResponseEntity.ok( body );
    }


    protected HttpHeaders toHeaders( List< String > cookies ) {
        HttpHeaders headers = new HttpHeaders();

        for ( String cookie : cookies ) {
            headers.add( HttpHeaders.SET_COOKIE, cookie );
        }

        return headers;
    }
}
