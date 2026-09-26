package org.romainlavabre.security.ory;

import kong.unirest.core.json.JSONArray;
import kong.unirest.core.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The rest client hands back the JSON types of its HTTP library (kong.unirest), or plain collections
 * once converted. Testing only for a Map or a List would silently lose the value.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public final class OryJson {

    /**
     * @return The value as a map, an empty one when absent or of another type
     */
    public static Map< String, Object > map( Object value ) {
        if ( value instanceof JSONObject jsonObject ) {
            return new HashMap<>( jsonObject.toMap() );
        }

        if ( value instanceof Map< ?, ? > map ) {
            Map< String, Object > result = new HashMap<>();

            for ( Map.Entry< ?, ? > entry : map.entrySet() ) {
                result.put( String.valueOf( entry.getKey() ), entry.getValue() );
            }

            return result;
        }

        return new HashMap<>();
    }


    /**
     * @return The value as a list, an empty one when absent or of another type
     */
    public static List< Object > list( Object value ) {
        if ( value instanceof JSONArray jsonArray ) {
            return new ArrayList<>( jsonArray.toList() );
        }

        if ( value instanceof List< ? > list ) {
            return new ArrayList<>( list );
        }

        return new ArrayList<>();
    }


    /**
     * @return The value as a list of strings, null items dropped
     */
    public static List< String > strings( Object value ) {
        List< String > result = new ArrayList<>();

        for ( Object item : list( value ) ) {
            String string = string( item );

            if ( string != null ) {
                result.add( string );
            }
        }

        return result;
    }


    /**
     * JSONObject.NULL stands for a JSON null, and prints "null": it must not become that string.
     */
    public static String string( Object value ) {
        if ( value == null || JSONObject.NULL.equals( value ) ) {
            return null;
        }

        return value.toString();
    }


    private OryJson() {
    }
}
