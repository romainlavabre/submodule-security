package org.romainlavabre.security.ory;

import org.romainlavabre.exception.HttpBadRequestException;

import java.util.regex.Pattern;

/**
 * An id is concatenated into the path of an admin API: a slash, a dot or an encoded character would
 * let a caller reach another admin endpoint than the one intended.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public final class OryId {
    private static final Pattern SAFE = Pattern.compile( "^[A-Za-z0-9_-]{1,255}$" );


    /**
     * @param requiredMessage Message thrown when the id is null or blank
     * @param invalidMessage  Message thrown when the id holds any other character than letters, digits, - and _
     */
    public static void assertSafe( String id, String requiredMessage, String invalidMessage ) {
        if ( id == null || id.isBlank() ) {
            throw new HttpBadRequestException( requiredMessage, false );
        }

        if ( !SAFE.matcher( id ).matches() ) {
            throw new HttpBadRequestException( invalidMessage, false );
        }
    }


    private OryId() {
    }
}
