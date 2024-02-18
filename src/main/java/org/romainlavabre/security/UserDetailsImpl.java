package org.romainlavabre.security;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
@Service
@Qualifier( "userDetailsService" )
public class UserDetailsImpl implements UserDetailsService {

    protected UserRepository userRepository;

    public UserDetailsImpl( final UserRepository userRepository ) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername( final String username ) throws UsernameNotFoundException {
        final User user = this.userRepository.findByUsername( username );

        if ( user == null ) {
            throw new UsernameNotFoundException( "The user with username " + username + " was not found" );
        }


        return org.springframework.security.core.userdetails.User
                .withUsername( username )
                .password( user.getPassword() )
                .authorities( user.getAuthorities() )
                .accountExpired( false )
                .accountLocked( false )
                .credentialsExpired( false )
                .disabled( !user.isEnabled() )
                .build();
    }

}
