package org.romainlavabre.security.config;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

public class InMemoryUser {
    private final String username;

    private final String password;

    private final List< String > roles;


    private InMemoryUser( String username, String password, List< String > roles ) {
        this.username = username;
        this.password = password;
        this.roles    = roles;
    }


    public static InMemoryUser of( String username, String password, List< String > roles ) {
        return new InMemoryUser( username, password, roles );
    }


    protected UserDetails toUserDetails() {
        User.UserBuilder users = User.withDefaultPasswordEncoder();
        String[]         arr   = new String[ roles.size() ];

        return users
                .username( username )
                .password( password )
                .roles( roles.toArray( arr ) )
                .build();
    }
}
