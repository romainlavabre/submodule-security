package org.romainlavabre.security;

import org.springframework.stereotype.Service;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
@Service
public class PasswordEncoderImpl implements PasswordEncoder {

    protected final org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;


    public PasswordEncoderImpl( org.springframework.security.crypto.password.PasswordEncoder passwordEncoder ) {
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public String encode( String plainText ) {
        return passwordEncoder.encode( plainText );
    }
}
