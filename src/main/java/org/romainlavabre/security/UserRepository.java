package org.romainlavabre.security;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
public interface UserRepository extends JpaRepository< User, Long > {

    Optional<User> findById( Long id);

    User findByUsername( String username );

    User findByForgotPasswordCode(String code);
}
