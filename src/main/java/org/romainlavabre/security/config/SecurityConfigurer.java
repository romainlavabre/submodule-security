package org.romainlavabre.security.config;

import org.romainlavabre.security.exception.NotInitializedException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SecurityConfigurer {
    private static SecurityConfigurer    INSTANCE;
    private        List< String >        publicEndpoints  = new ArrayList<>();
    private        Map< String, String > securedEndpoints = new HashMap<>();
    private        List< InMemoryUser >  inMemoryUsers    = new ArrayList<>();
    private        String                jwtSecret;
    private        int                   jwtLifeTime;


    public SecurityConfigurer() {
        INSTANCE = this;
    }


    public static SecurityConfigurer get() {
        if ( INSTANCE == null ) {
            throw new NotInitializedException();
        }

        return INSTANCE;
    }


    public static SecurityConfigurer init() {
        return new SecurityConfigurer();
    }


    protected List< String > getPublicEndpoint() {
        return publicEndpoints;
    }


    public SecurityConfigurer addPublicEndpoint( String publicEndpoint ) {
        publicEndpoints.add( publicEndpoint );

        return this;
    }


    protected Map< String, String > getSecuredEndpoints() {
        return securedEndpoints;
    }


    public SecurityConfigurer addSecuredEndpoint( String matcher, String role ) {
        securedEndpoints.put( matcher, role );

        return this;
    }


    protected List< InMemoryUser > getInMemoryUsers() {
        return inMemoryUsers;
    }


    public SecurityConfigurer addInMemoryUserWithHttpBasic( InMemoryUser inMemoryUser ) {
        inMemoryUsers.add( inMemoryUser );

        return this;
    }


    public String getJwtSecret() {
        return jwtSecret;
    }


    public SecurityConfigurer setJwtSecret( String jwtSecret ) {
        this.jwtSecret = jwtSecret;

        return this;
    }


    public int getJwtLifeTime() {
        return jwtLifeTime;
    }


    public SecurityConfigurer setJwtLifeTime( int jwtLifeTime ) {
        this.jwtLifeTime = jwtLifeTime;

        return this;
    }


    public void build() {
    }
}
