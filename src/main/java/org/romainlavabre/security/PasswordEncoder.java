package org.romainlavabre.security;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
public interface PasswordEncoder {
    String encode( String plainText );
}
