package org.romainlavabre.security.refreshtoken;

import jakarta.persistence.*;
import org.romainlavabre.security.User;

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
    protected String token;

    protected String deviceId;

    protected ZonedDateTime rotatedAt;

    @ManyToOne( cascade = { CascadeType.PERSIST } )
    @JoinColumn( nullable = false )
    protected User user;


    public long getId() {
        return id;
    }


    public String getToken() {
        return token;
    }


    public RefreshToken setToken( String token ) {
        this.token = token;
        return this;
    }


    public ZonedDateTime getRotatedAt() {
        return rotatedAt;
    }


    public String getDeviceId() {
        return deviceId;
    }


    public RefreshToken setDeviceId( String deviceId ) {
        this.deviceId = deviceId;
        return this;
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
