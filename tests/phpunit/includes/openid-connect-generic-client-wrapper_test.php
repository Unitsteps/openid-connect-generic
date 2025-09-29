<?php
/**
 * Class OpenID_Connect_Generic_Client_Wrapper_Test
 *
 * @package   OpenID_Connect_Generic
 */

/**
 * Plugin OIDC/oAuth client wrapper class test case.
 */
class OpenID_Connect_Generic_Client_Wrapper_Test extends WP_UnitTestCase {

	/**
	 * @var OpenID_Connect_Generic_Client_Wrapper
	 */
	private $client_wrapper;

	/**
	 * @var WP_User_Meta_Session_Tokens
	 */
	private $manager;

	/**
	 * Test case setup method.
	 *
	 * @return void
	 */
	public function setUp(): void {

		parent::setUp();

		remove_all_filters( 'session_token_manager' );
		$user_id        = self::factory()->user->create();
		$this->manager  = WP_Session_Tokens::get_instance( $user_id );

		$this->client_wrapper = OpenID_Connect_Generic::instance()->client_wrapper;

	}

	/**
	 * Test case cleanup method.
	 *
	 * @return void
	 */
	public function tearDown(): void {

		unset( $this->client_wrapper );

		parent::tearDown();

	}

	/**
	 * Test plugin alternate_redirect_uri_parse_request() method.
	 *
	 * @group ClientWrapperTests
	 */
	public function test_plugin_client_wrapper_alternate_redirect_uri_parse_request() {

		$this->assertTrue( true, 'Needs Unit Tests.' );

	}

	/**
	 * Test if by using the remember-me filter, the user session expiration
	 * is set to 14 days, which is the default of WordPress
	 *
	 * @group ClientWrapperTests
	 */
	public function test_plugin_client_wrapper_remember_me() {
		// Set the remember me option to true
		add_filter( 'openid-connect-generic-remember-me', '__return_true' );

		// Create a user and log in using the login function of the client wrapper
		$user = $this->factory()->user->create_and_get( array( 'user_login' => 'test-remember-me-user' ) );
		$this->client_wrapper->login_user( $user, array(
			'expires_in' => 5 * MINUTE_IN_SECONDS,
		), array(), array(), '' );

		// Retrieve the session tokens
		$manager = WP_Session_Tokens::get_instance( $user->ID );
		$token = $manager->get_all()[0];

		// Assert if the token is set to expire in 14 days, with some timing margin
		$this->assertGreaterThan( time() + 13 * DAY_IN_SECONDS, $token['expiration'] );
		$this->assertLessThan( time() + 15 * DAY_IN_SECONDS, $token['expiration'] );

		// Cleanup
		remove_filter( 'openid-connect-generic-remember-me', '__return_true' );
		$manager->destroy_all();
		wp_clear_auth_cookie();
	}

	/**
	 * Test proper handling of saving refresh tokens.
	 *
	 * @group ClientWrapperTests
	 */
	public function test_save_refresh_token() {
		$expiration 				= time() + DAY_IN_SECONDS;
		$token 							= $this->manager->create( $expiration );
		$token_response 		= array(
			"access_token"  => "TlBN45jURg",
			"token_type"    => "Bearer",
			"refresh_token" => "9yNOxJtZa5",
			"expires_in"    => 3600, // Expiration time of the Access Token in seconds since the response was generated. OPTIONAL.
		);

		$this->client_wrapper->save_refresh_token( $this->manager, $token, $token_response );
		$session = $this->manager->get( $token );

		$this->assertArrayHasKey( $this->client_wrapper::COOKIE_TOKEN_REFRESH_KEY, $session, "Session token is missing expected key!"	);
		$this->assertArrayHasKey( 'refresh_token', $session[ $this->client_wrapper::COOKIE_TOKEN_REFRESH_KEY ], "Refresh token is missing key!" );

		$this->manager->destroy( $token );
	}

	/**
	 * Test role mapping functionality.
	 *
	 * @return void
	 */
	public function test_role_mapping_from_keycloak_claims() {
		// Create a test user.
		$user = self::factory()->user->create_and_get();

		// Mock the settings to configure role mappings.
		$settings = OpenID_Connect_Generic::instance()->client_wrapper->settings;
		$settings->role_mapping_administrator = 'admin-role';
		$settings->role_mapping_editor = 'editor-role';
		$settings->role_mapping_author = 'author-role';
		$settings->role_mapping_contributor = 'contributor-role';
		$settings->role_mapping_subscriber = 'subscriber-role';

		// Test case 1: Administrator role assignment via resource_access.
		$user_claim_admin = array(
			'resource_access' => array(
				'my-client' => array(
					'roles' => array( 'admin-role', 'user-role' ),
				),
			),
		);

		// Use reflection to call the private method.
		$reflection = new ReflectionClass( $this->client_wrapper );
		$method = $reflection->getMethod( 'assign_user_role_from_claim' );
		$method->setAccessible( true );

		// Call the role assignment method.
		$method->invoke( $this->client_wrapper, $user, $user_claim_admin );

		// Refresh user object.
		$user = get_user_by( 'id', $user->ID );

		// Assert that the user has the administrator role.
		$this->assertTrue( in_array( 'administrator', $user->roles ), 'User should have administrator role' );

		// Test case 2: Editor role assignment via realm_access.
		$user_claim_editor = array(
			'realm_access' => array(
				'roles' => array( 'editor-role', 'user-role' ),
			),
		);

		// Reset user role to subscriber for testing.
		$user->set_role( 'subscriber' );

		// Call the role assignment method.
		$method->invoke( $this->client_wrapper, $user, $user_claim_editor );

		// Refresh user object.
		$user = get_user_by( 'id', $user->ID );

		// Assert that the user has the editor role.
		$this->assertTrue( in_array( 'editor', $user->roles ), 'User should have editor role' );

		// Test case 3: No role change when no matching roles found.
		$user_claim_no_match = array(
			'roles' => array( 'unknown-role', 'user-role' ),
		);

		// Set a known role first.
		$user->set_role( 'author' );

		// Call the role assignment method.
		$method->invoke( $this->client_wrapper, $user, $user_claim_no_match );

		// Refresh user object.
		$user = get_user_by( 'id', $user->ID );

		// Assert that the user still has the author role (no change).
		$this->assertTrue( in_array( 'author', $user->roles ), 'User should still have author role when no match found' );

		// Test case 4: Role priority (admin should be chosen over editor).
		$user_claim_priority = array(
			'resource_access' => array(
				'my-client' => array(
					'roles' => array( 'subscriber-role', 'admin-role', 'editor-role' ),
				),
			),
		);

		// Reset user role.
		$user->set_role( 'subscriber' );

		// Call the role assignment method.
		$method->invoke( $this->client_wrapper, $user, $user_claim_priority );

		// Refresh user object.
		$user = get_user_by( 'id', $user->ID );

		// Assert that the user has the administrator role (highest priority).
		$this->assertTrue( in_array( 'administrator', $user->roles ), 'User should have administrator role (highest priority)' );
	}

	/**
	 * Test role extraction from various claim structures.
	 *
	 * @return void
	 */
	public function test_extract_client_roles_from_claim() {
		// Use reflection to call the private method.
		$reflection = new ReflectionClass( $this->client_wrapper );
		$method = $reflection->getMethod( 'extract_client_roles_from_claim' );
		$method->setAccessible( true );

		// Test case 1: resource_access structure.
		$user_claim_resource = array(
			'resource_access' => array(
				'client1' => array(
					'roles' => array( 'role1', 'role2' ),
				),
				'client2' => array(
					'roles' => array( 'role3' ),
				),
			),
		);

		$roles = $method->invoke( $this->client_wrapper, $user_claim_resource );
		$this->assertContains( 'role1', $roles, 'Should extract role1 from resource_access' );
		$this->assertContains( 'role2', $roles, 'Should extract role2 from resource_access' );
		$this->assertContains( 'role3', $roles, 'Should extract role3 from resource_access' );

		// Test case 2: realm_access structure.
		$user_claim_realm = array(
			'realm_access' => array(
				'roles' => array( 'realm-role1', 'realm-role2' ),
			),
		);

		$roles = $method->invoke( $this->client_wrapper, $user_claim_realm );
		$this->assertContains( 'realm-role1', $roles, 'Should extract realm-role1 from realm_access' );
		$this->assertContains( 'realm-role2', $roles, 'Should extract realm-role2 from realm_access' );

		// Test case 3: direct roles structure.
		$user_claim_direct = array(
			'roles' => array( 'direct-role1', 'direct-role2' ),
		);

		$roles = $method->invoke( $this->client_wrapper, $user_claim_direct );
		$this->assertContains( 'direct-role1', $roles, 'Should extract direct-role1 from direct roles' );
		$this->assertContains( 'direct-role2', $roles, 'Should extract direct-role2 from direct roles' );

		// Test case 4: empty claims.
		$user_claim_empty = array();

		$roles = $method->invoke( $this->client_wrapper, $user_claim_empty );
		$this->assertEmpty( $roles, 'Should return empty array for empty claims' );

		// Test case 5: duplicate roles should be unique.
		$user_claim_duplicates = array(
			'resource_access' => array(
				'client1' => array(
					'roles' => array( 'duplicate-role', 'role1' ),
				),
			),
			'roles' => array( 'duplicate-role', 'role2' ),
		);

		$roles = $method->invoke( $this->client_wrapper, $user_claim_duplicates );
		$this->assertEquals( 1, array_count_values( $roles )['duplicate-role'], 'Duplicate roles should be unique' );
	}

}
