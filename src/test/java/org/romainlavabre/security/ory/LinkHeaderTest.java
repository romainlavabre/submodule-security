package org.romainlavabre.security.ory;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class LinkHeaderTest {

    @Test
    public void it_reads_the_token_of_the_next_link() {
        String header = "<http://kratos:4434/admin/identities?page_size=20&page_token=abc>; rel=\"first\","
                + "<http://kratos:4434/admin/identities?page_size=20&page_token=def>; rel=\"next\"";

        Assert.assertEquals( "def", LinkHeader.nextPageToken( header ) );
    }


    @Test
    public void it_answers_null_on_the_last_page() {
        String header = "<http://kratos:4434/admin/identities?page_size=20&page_token=abc>; rel=\"first\"";

        Assert.assertNull( LinkHeader.nextPageToken( header ) );
    }


    @Test
    public void it_answers_null_without_header() {
        Assert.assertNull( LinkHeader.nextPageToken( ( String ) null ) );
        Assert.assertNull( LinkHeader.nextPageToken( "" ) );
    }


    @Test
    public void it_decodes_an_encoded_token() {
        String header = "<http://hydra:4445/admin/clients?page_token=a%3Db%2Fc&page_size=10>; rel=\"next\"";

        Assert.assertEquals( "a=b/c", LinkHeader.nextPageToken( header ) );
    }


    @Test
    public void it_answers_null_when_the_next_link_carries_no_token() {
        Assert.assertNull( LinkHeader.nextPageToken( "<http://hydra:4445/admin/clients?page_size=10>; rel=\"next\"" ) );
    }
}
