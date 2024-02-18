package org.romainlavabre.security;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
public interface UserRepository extends JpaRepository< User, Long > {

    User findByUsername( String username );
}
