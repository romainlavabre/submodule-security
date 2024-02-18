package org.romainlavabre.security;

import org.springframework.stereotype.Service;
import org.springframework.web.context.annotation.RequestScope;

import java.util.Set;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
@Service
@RequestScope
public class SecurityImpl implements Security {

    protected User user;

    @Override
    public long getId() {
        return this.user.getId();
    }

    @Override
    public String getUsername() {
        return this.user.getUsername();
    }

    @Override
    public Set< String > getRoles() {
        return this.user.getRoles();
    }

    @Override
    public boolean hasRole( final String role ) {
        return this.user.getRoles().contains( role );
    }

    @Override
    public boolean hasUserConnected() {
        return this.user != null;
    }


    public void hydrate( final long id, final String username, final Set< String > roles ) {
        final User user = new User();

        user.setId( id );
        user.setUsername( username );
        roles.forEach( user::addRole );

        this.user = user;
    }
}
