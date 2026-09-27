package org.romainlavabre.security.identity;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.romainlavabre.exception.HttpBadRequestException;
import org.romainlavabre.exception.HttpConflictException;
import org.romainlavabre.exception.HttpInternalServerErrorException;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.romainlavabre.security.message.Error;
import org.romainlavabre.security.ory.FakeOryServer;
import org.romainlavabre.security.ory.Page;

import java.util.Map;
import java.util.Optional;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class KratosIdentitiesImplTest {
    private static final String ID = "0d1f4c6a-7b2e-4d3a-9f8c-1e2b3a4d5c6e";

    private static final String IDENTITY = "{\"id\":\"" + ID + "\",\"state\":\"active\","
            + "\"traits\":{\"email\":\"jane@marea.fr\"},\"metadata_admin\":{\"role\":\"ROLE_ADMIN\"},"
            + "\"created_at\":\"2026-09-26T10:00:00Z\",\"updated_at\":\"2026-09-26T11:00:00Z\"}";

    private FakeOryServer    kratos;
    private KratosIdentities identities;


    @Before
    public void setUp() throws Exception {
        kratos = new FakeOryServer();

        SecurityConfigurer.init().setKratosAdminUrl( kratos.url() ).build();

        identities = new KratosIdentitiesImpl();
    }


    @After
    public void tearDown() {
        kratos.stop();
    }


    @Test
    public void it_lists_a_page_with_its_next_token() {
        kratos.respond( 200, "[" + IDENTITY + "]", "<" + kratos.url() + "/admin/identities?page_size=20&page_token=next-one>; rel=\"next\"" );

        Page< KratosIdentity > page = identities.list( 20, "current", "jane@marea.fr" );

        Assert.assertEquals( 1, page.items().size() );
        Assert.assertEquals( "next-one", page.nextPageToken() );
        Assert.assertEquals( "GET", kratos.last().method() );
        Assert.assertEquals( "/admin/identities", kratos.last().path() );
        Assert.assertTrue( kratos.last().query().contains( "page_size=20" ) );
        Assert.assertTrue( kratos.last().query().contains( "page_token=current" ) );
        Assert.assertTrue( kratos.last().query().contains( "credentials_identifier=jane%40marea.fr" ) );
    }


    @Test
    public void it_reads_every_field_of_an_identity() {
        kratos.respond( 200, IDENTITY );

        KratosIdentity identity = identities.find( ID ).orElseThrow();

        Assert.assertEquals( ID, identity.id() );
        Assert.assertEquals( "jane@marea.fr", identity.email() );
        Assert.assertTrue( identity.isActive() );
        Assert.assertEquals( Map.of( "role", "ROLE_ADMIN" ), identity.metadataAdmin() );
        Assert.assertEquals( "2026-09-26T10:00:00Z", identity.createdAt() );
        Assert.assertEquals( "2026-09-26T11:00:00Z", identity.updatedAt() );
    }


    @Test
    public void it_reads_a_null_metadata_admin_as_empty() {
        kratos.respond( 200, "{\"id\":\"" + ID + "\",\"state\":\"inactive\",\"traits\":{\"email\":\"a@b.fr\"},\"metadata_admin\":null}" );

        KratosIdentity identity = identities.find( ID ).orElseThrow();

        Assert.assertTrue( identity.metadataAdmin().isEmpty() );
        Assert.assertFalse( identity.isActive() );
    }


    @Test
    public void it_answers_empty_on_an_unknown_id() {
        kratos.respond( 404, "{}" );

        Assert.assertEquals( Optional.empty(), identities.find( ID ) );
    }


    @Test
    public void it_answers_empty_on_an_unknown_email() {
        kratos.respond( 200, "[]" );

        Assert.assertEquals( Optional.empty(), identities.findByEmail( "nobody@marea.fr" ) );
    }


    @Test
    public void it_patches_the_metadata_admin() {
        kratos.respond( 200, IDENTITY );

        identities.replaceMetadataAdmin( ID, Map.of( "role", "ROLE_BILLER" ) );

        Assert.assertEquals( "PATCH", kratos.last().method() );
        Assert.assertEquals( "/admin/identities/" + ID, kratos.last().path() );
        Assert.assertTrue( kratos.last().body().contains( "\"path\":\"/metadata_admin\"" ) );
        Assert.assertTrue( kratos.last().body().contains( "\"role\":\"ROLE_BILLER\"" ) );
    }


    @Test
    public void it_patches_the_email_as_a_verified_address() {
        kratos.respond( 200, IDENTITY );

        identities.updateEmail( ID, " john@marea.fr " );

        Assert.assertEquals( "PATCH", kratos.last().method() );
        Assert.assertEquals( "/admin/identities/" + ID, kratos.last().path() );
        Assert.assertTrue( kratos.last().body().contains( "\"path\":\"/traits/email\"" ) );
        Assert.assertTrue( kratos.last().body().contains( "\"path\":\"/verifiable_addresses\"" ) );
        Assert.assertTrue( kratos.last().body().contains( "\"value\":\"john@marea.fr\"" ) );
        Assert.assertTrue( kratos.last().body().contains( "\"verified\":true" ) );
    }


    @Test
    public void it_refuses_an_email_another_identity_logs_in_with() {
        kratos.respond( 409, "{}" );

        HttpConflictException exception =
                Assert.assertThrows( HttpConflictException.class, () -> identities.updateEmail( ID, "taken@marea.fr" ) );

        Assert.assertEquals( Error.IDP_IDENTITY_ALREADY_EXISTS, exception.getMessage() );
    }


    @Test
    public void it_requires_an_email_without_calling_kratos() {
        HttpBadRequestException exception =
                Assert.assertThrows( HttpBadRequestException.class, () -> identities.updateEmail( ID, " " ) );

        Assert.assertEquals( Error.IDP_USERNAME_REQUIRED, exception.getMessage() );
        Assert.assertEquals( 0, kratos.count() );
    }


    @Test
    public void it_patches_the_state() {
        kratos.respond( 200, IDENTITY );

        identities.setActive( ID, false );

        Assert.assertTrue( kratos.last().body().contains( "\"path\":\"/state\"" ) );
        Assert.assertTrue( kratos.last().body().contains( "\"value\":\"inactive\"" ) );
    }


    @Test
    public void it_tolerates_deleting_an_absent_identity() {
        kratos.respond( 404, "{}" );

        identities.delete( ID );

        Assert.assertEquals( "DELETE", kratos.last().method() );
    }


    @Test
    public void it_revokes_the_sessions() {
        identities.revokeSessions( ID );

        Assert.assertEquals( "DELETE", kratos.last().method() );
        Assert.assertEquals( "/admin/identities/" + ID + "/sessions", kratos.last().path() );
    }


    @Test
    public void it_fails_when_kratos_fails() {
        kratos.respond( 500, "{}" );

        HttpInternalServerErrorException exception =
                Assert.assertThrows( HttpInternalServerErrorException.class, () -> identities.find( ID ) );

        Assert.assertEquals( Error.IDP_IDENTITY_FAILED, exception.getMessage() );
    }


    /**
     * The id lands in the admin URL: a traversal must never reach Kratos.
     */
    @Test
    public void it_refuses_an_unsafe_id_without_calling_kratos() {
        HttpBadRequestException exception =
                Assert.assertThrows( HttpBadRequestException.class, () -> identities.delete( "../sessions" ) );

        Assert.assertEquals( Error.IDP_IDENTITY_ID_INVALID, exception.getMessage() );
        Assert.assertEquals( 0, kratos.count() );
    }


    @Test
    public void it_requires_an_id() {
        HttpBadRequestException exception = Assert.assertThrows( HttpBadRequestException.class, () -> identities.find( null ) );

        Assert.assertEquals( Error.IDP_IDENTITY_ID_REQUIRED, exception.getMessage() );
    }
}
