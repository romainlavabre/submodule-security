package org.romainlavabre.security;

import jakarta.persistence.*;
import org.romainlavabre.encoder.annotation.Group;
import org.romainlavabre.encoder.annotation.Json;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * @author Romain Lavabre <romainlavabre98@gmail.com>
 */
@Entity
public class User {


    @Json( groups = {
            @Group
    } )
    @Id
    @GeneratedValue( strategy = GenerationType.IDENTITY )
    private long id;

    @Json( groups = {
            @Group
    } )
    @Column( nullable = false, unique = true )
    private String username;

    @Column( nullable = false )
    private String password;

    @Json( groups = {
            @Group
    } )
    @ElementCollection
    private final Set< String > roles;
    private       boolean       enable;


    public User() {
        roles  = new HashSet<>();
        enable = true;
    }


    public long getId() {
        return this.id;
    }


    public void setId( final long id ) {
        this.id = id;
    }


    public void setUsername( final String username ) {
        this.username = username;
    }


    public void setPassword( final String password ) {
        this.password = password;
    }


    public Set< String > getRoles() {
        return this.roles;
    }


    public void addRole( final String role ) {
        this.roles.add( role );
    }


    public void setEnabled( final boolean enable ) {
        this.enable = enable;
    }


    public Collection< ? extends GrantedAuthority > getAuthorities() {
        final Collection< GrantedAuthority > collection = new ArrayList<>();

        this.roles.forEach( role -> {
            collection.add( new SimpleGrantedAuthority( role ) );
        } );

        return collection;
    }


    public String getPassword() {
        return this.password;
    }


    public String getUsername() {
        return this.username;
    }


    public boolean isEnabled() {
        return this.enable;
    }
}
