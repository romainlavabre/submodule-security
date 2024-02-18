package org.romainlavabre.security.attribute;

import org.romainlavabre.security.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class DefaultRoles implements ClaimBuilder {

    @Override
    public String name() {
        return "roles";
    }


    @Override
    public Object value( User user ) {
        List< String > roles = new ArrayList<>();

        for ( GrantedAuthority grantedAuthority : user.getAuthorities() ) {
            roles.add( grantedAuthority.getAuthority() );
        }

        return roles;
    }
}
