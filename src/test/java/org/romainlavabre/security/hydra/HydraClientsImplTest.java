package org.romainlavabre.security.hydra;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.romainlavabre.exception.HttpBadRequestException;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.romainlavabre.security.message.Error;
import org.romainlavabre.security.ory.FakeOryServer;
import org.romainlavabre.security.ory.Page;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class HydraClientsImplTest {
    private static final String CLIENT_ID = "4f7c1d2e-9a3b-4c5d-8e6f-7a8b9c0d1e2f";

    private static final String CLIENT = "{\"client_id\":\"" + CLIENT_ID + "\",\"client_name\":\"Plomberie Dupont\","
            + "\"scope\":\"marea:read marea:write\",\"audience\":[\"marea\"],"
            + "\"metadata\":{\"role\":\"ROLE_PRESCRIBER\"},\"created_at\":\"2026-09-26T10:00:00Z\"}";

    private FakeOryServer hydra;
    private HydraClients  clients;


    @Before
    public void setUp() throws Exception {
        hydra = new FakeOryServer();

        SecurityConfigurer.init().setHydraAdminUrl( hydra.url() ).build();

        clients = new HydraClientsImpl();
    }


    @After
    public void tearDown() {
        hydra.stop();
    }


    @Test
    public void it_creates_a_client_with_its_metadata() {
        hydra.respond( 201, "{\"client_id\":\"" + CLIENT_ID + "\",\"client_secret\":\"s3cr3t\"}" );

        HydraClients.Credentials credentials = clients.create(
                "Plomberie Dupont",
                List.of( "marea:read", "marea:write" ),
                List.of( "marea" ),
                Map.of( "role", "ROLE_PRESCRIBER" )
        );

        Assert.assertEquals( CLIENT_ID, credentials.clientId() );
        Assert.assertEquals( "s3cr3t", credentials.clientSecret() );
        Assert.assertEquals( "POST", hydra.last().method() );
        Assert.assertTrue( hydra.last().body().contains( "\"scope\":\"marea:read marea:write\"" ) );
        Assert.assertTrue( hydra.last().body().contains( "\"metadata\":{\"role\":\"ROLE_PRESCRIBER\"}" ) );
        Assert.assertTrue( hydra.last().body().contains( "\"grant_types\":[\"client_credentials\"]" ) );
    }


    @Test
    public void it_lists_a_page_with_its_next_token() {
        hydra.respond( 200, "[" + CLIENT + "]", "<" + hydra.url() + "/admin/clients?page_size=10&page_token=p2>; rel=\"next\"" );

        Page< HydraClient > page = clients.list( 10, null, null );

        Assert.assertEquals( 1, page.items().size() );
        Assert.assertEquals( "p2", page.nextPageToken() );
        Assert.assertFalse( hydra.last().query().contains( "page_token" ) );
    }


    @Test
    public void it_reads_every_field_of_a_client() {
        hydra.respond( 200, CLIENT );

        HydraClient client = clients.find( CLIENT_ID ).orElseThrow();

        Assert.assertEquals( CLIENT_ID, client.clientId() );
        Assert.assertEquals( "Plomberie Dupont", client.name() );
        Assert.assertEquals( List.of( "marea:read", "marea:write" ), client.scopes() );
        Assert.assertEquals( List.of( "marea" ), client.audiences() );
        Assert.assertEquals( Map.of( "role", "ROLE_PRESCRIBER" ), client.metadata() );
        Assert.assertEquals( "2026-09-26T10:00:00Z", client.createdAt() );
    }


    @Test
    public void it_reads_an_empty_scope_as_no_scope() {
        hydra.respond( 200, "{\"client_id\":\"" + CLIENT_ID + "\",\"scope\":\"\",\"audience\":[],\"metadata\":null}" );

        HydraClient client = clients.find( CLIENT_ID ).orElseThrow();

        Assert.assertTrue( client.scopes().isEmpty() );
        Assert.assertTrue( client.metadata().isEmpty() );
    }


    @Test
    public void it_answers_empty_on_an_unknown_client() {
        hydra.respond( 404, "{}" );

        Assert.assertEquals( Optional.empty(), clients.find( CLIENT_ID ) );
    }


    @Test
    public void it_patches_the_scopes_as_a_single_string() {
        hydra.respond( 200, CLIENT );

        clients.updateScopes( CLIENT_ID, List.of( "marea:read" ) );

        Assert.assertEquals( "PATCH", hydra.last().method() );
        Assert.assertEquals( "/admin/clients/" + CLIENT_ID, hydra.last().path() );
        Assert.assertTrue( hydra.last().body().contains( "\"path\":\"/scope\"" ) );
        Assert.assertTrue( hydra.last().body().contains( "\"value\":\"marea:read\"" ) );
    }


    @Test
    public void it_patches_the_audiences() {
        hydra.respond( 200, CLIENT );

        clients.updateAudiences( CLIENT_ID, List.of( "marea" ) );

        Assert.assertTrue( hydra.last().body().contains( "\"path\":\"/audience\"" ) );
        Assert.assertTrue( hydra.last().body().contains( "\"value\":[\"marea\"]" ) );
    }


    @Test
    public void it_patches_the_metadata() {
        hydra.respond( 200, CLIENT );

        clients.replaceMetadata( CLIENT_ID, Map.of( "role", "ROLE_PRESCRIBER" ) );

        Assert.assertTrue( hydra.last().body().contains( "\"path\":\"/metadata\"" ) );
    }


    @Test
    public void it_rotates_the_secret_and_hands_it_back() {
        hydra.respond( 200, CLIENT );

        String secret = clients.rotateSecret( CLIENT_ID );

        Assert.assertEquals( 64, secret.length() );
        Assert.assertTrue( hydra.last().body().contains( "\"path\":\"/client_secret\"" ) );
        Assert.assertTrue( hydra.last().body().contains( secret ) );
    }


    @Test
    public void it_refuses_an_unsafe_client_id_without_calling_hydra() {
        HttpBadRequestException exception =
                Assert.assertThrows( HttpBadRequestException.class, () -> clients.delete( "a/../b" ) );

        Assert.assertEquals( Error.IDP_CLIENT_ID_INVALID, exception.getMessage() );
        Assert.assertEquals( 0, hydra.count() );
    }
}
