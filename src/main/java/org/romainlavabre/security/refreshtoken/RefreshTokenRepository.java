package org.romainlavabre.security.refreshtoken;

import org.romainlavabre.security.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository< RefreshToken, Long > {

    List< RefreshToken > findAllByUser( User user );


    RefreshToken findByToken( String refreshTokenStr );


    RefreshToken findByUserAndRotatedAtIsNull( User user );
}
