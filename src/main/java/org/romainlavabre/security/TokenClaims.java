package org.romainlavabre.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Reads the claims whose shape depends on who minted the token.
 * <p>
 * {@code aud} is a single string or an array, depending on the issuer. The granted scopes are
 * {@code scp} as an array on Hydra, and {@code scope} as a space separated string on other issuers.
 * Every reader of those two claims goes through here, so that a new issuer is handled in one place.
 * <p>
 * An absent claim answers an empty list, never null and never an exception: a token is caller input,
 * and a missing claim is a caller holding no grant, not a server fault.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public final class TokenClaims {

    public static final String CLAIM_AUDIENCE = "aud";
    public static final String CLAIM_SCP      = "scp";
    public static final String CLAIM_SCOPE    = "scope";


    public static List< String > audiences( Map< String, Object > claims ) {
        return values( claims, CLAIM_AUDIENCE, false );
    }


    /**
     * {@code scp} wins over {@code scope}: Hydra carries the first, as the authoritative array form.
     */
    public static List< String > scopes( Map< String, Object > claims ) {
        List< String > scp = values( claims, CLAIM_SCP, true );

        return scp.isEmpty() ? values( claims, CLAIM_SCOPE, true ) : scp;
    }


    public static boolean hasScope( Map< String, Object > claims, String scope ) {
        return hasAnyScope( claims, scope );
    }


    public static boolean hasAnyScope( Map< String, Object > claims, String... expected ) {
        List< String > granted = scopes( claims );

        for ( String candidate : expected ) {
            for ( String scope : granted ) {
                if ( scope.equalsIgnoreCase( candidate ) ) {
                    return true;
                }
            }
        }

        return false;
    }


    /**
     * @param spaceSeparated TRUE for the scopes, whose string form packs several values. An audience
     *                       is one value, and splitting it would invent audiences that were never
     *                       granted.
     */
    private static List< String > values( Map< String, Object > claims, String name, boolean spaceSeparated ) {
        if ( claims == null ) {
            return List.of();
        }

        Object claim = claims.get( name );

        if ( claim == null ) {
            return List.of();
        }

        List< String > values = new ArrayList<>();

        if ( claim instanceof Collection< ? > collection ) {
            for ( Object value : collection ) {
                add( values, value, spaceSeparated );
            }
        } else {
            add( values, claim, spaceSeparated );
        }

        return List.copyOf( values );
    }


    private static void add( List< String > values, Object value, boolean spaceSeparated ) {
        if ( value == null ) {
            return;
        }

        String raw = value.toString().trim();

        if ( raw.isEmpty() ) {
            return;
        }

        if ( !spaceSeparated ) {
            values.add( raw );

            return;
        }

        for ( String part : raw.split( "\\s+" ) ) {
            if ( !part.isEmpty() ) {
                values.add( part );
            }
        }
    }


    private TokenClaims() {
    }
}
