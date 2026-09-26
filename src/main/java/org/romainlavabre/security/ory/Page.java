package org.romainlavabre.security.ory;

import java.util.List;

/**
 * A page of an Ory admin listing. Ory paginates by token only: there is a next page, never a previous
 * one, and no total.
 *
 * @param items         The items of this page
 * @param nextPageToken Token of the next page, null on the last one
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public record Page< T >( List< T > items, String nextPageToken ) {

    public boolean hasNext() {
        return nextPageToken != null;
    }
}
