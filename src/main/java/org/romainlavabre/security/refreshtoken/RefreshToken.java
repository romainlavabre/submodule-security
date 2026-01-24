package org.romainlavabre.security.refreshtoken;

import jakarta.persistence.*;
import org.romainlavabre.security.User;
import org.romainlavabre.tokengen.TokenGenerator;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Entity
public class RefreshToken {

    @Id
    @GeneratedValue( strategy = GenerationType.IDENTITY )
    protected long id;

    @Column( length = 64, unique = true )
    protected final String token;

    private ZonedDateTime rotatedAt;

    @ManyToOne( cascade = { CascadeType.PERSIST } )
    @JoinColumn( nullable = false )
    private User user;


    public RefreshToken() {
        token = TokenGenerator.generateSecureCode( 64 );
    }


    public long getId() {
        return id;
    }


    public String getToken() {
        return token;
    }


    public ZonedDateTime getRotatedAt() {
        return rotatedAt;
    }


    public RefreshToken markAsUsed() {
        this.rotatedAt = ZonedDateTime.now( ZoneOffset.UTC );
        return this;
    }


    public User getUser() {
        return user;
    }


    public RefreshToken setUser( User user ) {
        this.user = user;
        return this;
    }
}
