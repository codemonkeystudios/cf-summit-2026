
/*
	passkey.cfc
	==========================================================
	Educational/demo service for a passkey (WebAuthn) flow on Adobe ColdFusion 2023+.

	This component intentionally simplifies a production-grade WebAuthn implementation.
	It is intended to teach the SHAPE of the protocol, not to be deployed as-is.

	For a production-ready ColdFusion implementation you would need to:
		- Validate that the response challenge matches the challenge issued for that session.
		- Validate that the response origin matches the expected site origin (e.g. https://example.com).
		- Validate that the RP ID hash inside authenticatorData matches SHA-256(rp.id).
		- Validate clientData.type:
	 "webauthn.create" for registration
	 "webauthn.get" for authentication
		- Parse authenticatorData flags (UP / UV / AT / ED) and enforce your policy.
		- Decide how to handle attestation (none / indirect / direct / enterprise).
		- Parse the COSE-encoded public key out of attestationObject -> authData -> attestedCredentialData
	 and store it for later signature verification.
		- Verify the assertion signature using the stored COSE public key (ES256 / RS256 / EdDSA, etc.).
		- Track and verify the authenticator sign counter to detect cloned authenticators.
		- Persist credentials and challenges in a real database, not application/session scope.
		- Require HTTPS in production. Localhost is allowed for development only.
*/
component
	displayname = "passkey"
	output = "false"
	hint = "CF Summit 2026 educational passkey/WebAuthn service. Not production-ready."
{

	// LIFECYCLE
	public passkey function init(
		string relying_party_id = "localhost",
		string relying_party_name = "ColdFusion Passkey Demo"
	) {
		/*
			WebAuthn is DOMAIN-BOUND: the Relying Party ID must match the host the browser
			sees (e.g. "localhost", a LAN hostname, your ngrok host, or your demo domain).
			"localhost" is the right default for a local demo; pass another value when you
			run this anywhere else, or the browser will refuse to create/use the passkey.
			The expected ORIGIN host is derived from this id when we check clientDataJSON.
		*/
		variables.relying_party_id = arguments.relying_party_id;
		variables.relying_party_name = arguments.relying_party_name;

		// Application-scoped fake "user store". In production this MUST be a database table.
		if ( !structKeyExists( application, "passkey_demo_users" ) ) {
			application.passkey_demo_users = {};
		}

		return this;
	}


	// REGISTRATION
	public struct function start_registration( required string username )
		hint = "Generate PublicKeyCredentialCreationOptions for a new passkey."
	{

		var normalized_username = trim( arguments.username );

		// Generate a fresh random user_id (32 random bytes is plenty; spec allows up to 64).
		var user_id_bytes = generate_random_bytes( 32 );
		var user_id_base64url = bytes_to_base64url( user_id_bytes );

		// Generate the registration challenge. The browser/authenticator will sign it.
		var challenge_bytes = generate_random_bytes( 32 );
		var challenge_base64url = bytes_to_base64url( challenge_bytes );

		// Stash the challenge + intended username on the session so we can compare on finish.
		// NOTE: production code would also bind this to RP ID, origin, and a short TTL,
		// and would store it in a server-side challenge table, not session scope.
		session.passkey_challenge = {
			"challenge": challenge_base64url,
			"username": normalized_username,
			"user_id": user_id_base64url,
			"purpose": "registration",
			"issued_at": now()
		};

		// WebAuthn PublicKeyCredentialCreationOptions structure.
		// rp.id MUST match the browser-visible host (configured in init - see the note
		// there). "localhost" is only valid during local development.
		var creation_options = {
			"challenge": challenge_base64url,
			"rp": {
				"name": variables.relying_party_name,
				"id": variables.relying_party_id
			},
			"user": {
				"id": user_id_base64url,
				"name": normalized_username,
				"displayName": normalized_username
			},
			"pubKeyCredParams": [
				{ "type": "public-key", "alg": -7 },
				{ "type": "public-key", "alg": -257 }
			],
			"authenticatorSelection": {
				"userVerification": "preferred",
				"residentKey": "preferred"
			},
			"timeout": 60000,
			"attestation": "none"
		};

		return creation_options;
	}


	public struct function finish_registration( required struct credential_response )
		hint = "Receive the attestation response from the browser and store the credential (demo only)."
	{

		// The browser sent us:
		// id, raw_id, type,
		// response.client_data_json, response.attestation_object
		if ( !structKeyExists( session, "passkey_challenge" ) ) {
			return { "ok": false, "error": "No active registration challenge in session." };
		}

		var pending_challenge = session.passkey_challenge;

		if ( pending_challenge.purpose != "registration" ) {
			return { "ok": false, "error": "Session challenge is not for registration." };
		}

		/*
			--- DEMO SHORTCUT: we are NOT performing real cryptographic validation here. ---
			In production you MUST:
			 1. Base64URL-decode response.client_data_json -> JSON.
			 2. Verify clientData.type == "webauthn.create".
			 3. Verify clientData.challenge == the challenge we issued.
			 4. Verify clientData.origin matches the expected origin (e.g. "https://example.com").
			 5. Decode response.attestation_object (CBOR) and pull out authData.
			 6. Verify the RP ID hash inside authData matches SHA-256(rp.id).
			 7. Verify authData flags (UP set; UV set if you require user verification).
			 8. Parse the attestedCredentialData out of authData and extract the COSE public key.
			 9. Apply your attestation policy (none / indirect / direct / enterprise).
			 10. Persist credential ID, COSE public key, sign_count, and metadata in a database.
		*/

		// Decode clientDataJSON and ENFORCE the basic checks it contains. This is NOT full
		// WebAuthn verification (no attestation / authenticator-data / signature parsing),
		// but the demo must not claim success when its own decoded checks fail.
		var client_data_inspection = inspect_client_data_json(
			arguments.credential_response.response.client_data_json,
			"webauthn.create",
			pending_challenge.challenge
		);

		var basic_check_failure = first_failed_client_data_check( client_data_inspection );
		if ( len( basic_check_failure ) ) {
			return { "ok": false, "error": basic_check_failure, "notes": client_data_inspection };
		}

		var registering_username = pending_challenge.username;
		var registering_user_id = pending_challenge.user_id;

		// Store the demo credential. In production this would be a row in a credentials table
		// with a parsed COSE public key, not a placeholder string.
		application.passkey_demo_users[ registering_username ] = {
			"user_id": registering_user_id,
			"username": registering_username,
			"credential_id": normalize_credential_id( arguments.credential_response.id ),
			"public_key": "DEMO_PLACEHOLDER_replace_with_parsed_COSE_public_key_from_attestationObject",
			"sign_count": 0,
			"created_at": now(),
			"raw_attestation": arguments.credential_response.response.attestation_object
		};

		// One-time challenge: clear it.
		structDelete( session, "passkey_challenge" );

		// Match common UX: registering a passkey also signs the user in.
		session.passkey_user = registering_username;

		return {
			"ok": true,
			"username": registering_username,
			"notes": client_data_inspection
		};
	}


	// AUTHENTICATION
	public struct function start_authentication( required string username )
		hint = "Generate PublicKeyCredentialRequestOptions for an existing passkey."
	{

		var normalized_username = trim( arguments.username );

		if ( !structKeyExists( application.passkey_demo_users, normalized_username ) ) {
			throw(
				type = "passkey.no_such_user",
				message = "No passkey registered for #normalized_username#."
			);
		}

		var stored_user = application.passkey_demo_users[ normalized_username ];

		// Fresh challenge for this assertion.
		var challenge_bytes = generate_random_bytes( 32 );
		var challenge_base64url = bytes_to_base64url( challenge_bytes );

		session.passkey_challenge = {
			"challenge": challenge_base64url,
			"username": normalized_username,
			"purpose": "authentication",
			"issued_at": now()
		};

		var request_options = {
			"challenge": challenge_base64url,
			"allowCredentials": [
				{
					"type": "public-key",
					"id": stored_user.credential_id
				}
			],
			"userVerification": "preferred",
			"timeout": 60000
		};

		return request_options;
	}


	public struct function finish_authentication( required struct assertion_response )
		hint = "Receive the assertion response and (demo) mark the session authenticated."
	{

		if ( !structKeyExists( session, "passkey_challenge" ) ) {
			return { "ok": false, "error": "No active authentication challenge in session." };
		}

		var pending_challenge = session.passkey_challenge;

		if ( pending_challenge.purpose != "authentication" ) {
			return { "ok": false, "error": "Session challenge is not for authentication." };
		}

		var authenticating_username = pending_challenge.username;

		if ( !structKeyExists( application.passkey_demo_users, authenticating_username ) ) {
			return { "ok": false, "error": "User not found." };
		}

		var stored_user = application.passkey_demo_users[ authenticating_username ];

		/*
			--- DEMO SHORTCUT: we are NOT verifying the assertion signature here. ---
			In production you MUST:
			 1. Verify the credential_id we received matches one stored for this user.
			 2. Base64URL-decode response.client_data_json -> JSON.
			 3. Verify clientData.type == "webauthn.get".
			 4. Verify clientData.challenge == the challenge we issued.
			 5. Verify clientData.origin matches the expected site origin.
			 6. Decode response.authenticator_data and check:
				- RP ID hash matches SHA-256(rp.id)
				- UP flag set; UV flag set if you require user verification
				- sign_count is greater than the previously stored sign_count
			 7. Compute SHA-256(response.client_data_json) -> clientDataHash.
			 8. Verify the signature over (authenticatorData || clientDataHash) using the
			 stored COSE public key (with the correct algorithm: ES256, RS256, EdDSA, ...).
			 9. Update the stored sign_count.
		*/

		// Demo sanity check #1: confirm the credential id matches what we stored.
		var received_credential_id = normalize_credential_id( arguments.assertion_response.id );

		if ( received_credential_id != stored_user.credential_id ) {
			return { "ok": false, "error": "Credential ID does not match the stored credential for this user." };
		}

		// Decode clientDataJSON and ENFORCE the basic checks it contains. Still NOT full
		// WebAuthn verification (the assertion signature is not checked here), but the demo
		// must not report a successful sign-in when its own decoded checks fail.
		var client_data_inspection = inspect_client_data_json(
			arguments.assertion_response.response.client_data_json,
			"webauthn.get",
			pending_challenge.challenge
		);

		var basic_check_failure = first_failed_client_data_check( client_data_inspection );
		if ( len( basic_check_failure ) ) {
			return { "ok": false, "error": basic_check_failure, "notes": client_data_inspection };
		}

		// Demo: increment the (unverified) sign counter.
		// Production must extract this from authenticatorData and compare it to the previous value.
		application.passkey_demo_users[ authenticating_username ].sign_count = application.passkey_demo_users[ authenticating_username ].sign_count + 1;

		// Mark the session authenticated.
		session.passkey_user = authenticating_username;
		structDelete( session, "passkey_challenge" );

		return {
			"ok": true,
			"username": authenticating_username,
			"sign_count": application.passkey_demo_users[ authenticating_username ].sign_count,
			"notes": client_data_inspection
		};
	}


	// SESSION HELPERS
	public struct function get_current_user()
		hint = "Return the currently signed-in demo user, if any."
	{

		if ( structKeyExists( session, "passkey_user" ) && len( session.passkey_user ) ) {
			if ( structKeyExists( application.passkey_demo_users, session.passkey_user ) ) {
				var stored_user = application.passkey_demo_users[ session.passkey_user ];

				return {
					"signed_in": true,
					"username": stored_user.username,
					"sign_count": stored_user.sign_count,
					"created_at": dateTimeFormat( stored_user.created_at, "yyyy-mm-dd HH:nn:ss" )
				};
			}
		}

		return { "signed_in": false };
	}


	public struct function logout()
		hint = "Clear the demo session."
	{
		structDelete( session, "passkey_user" );
		structDelete( session, "passkey_challenge" );

		return { "ok": true };
	}


	// HTTP / JSON HELPERS
	public any function read_json_request_body()
		hint = "Parse the raw HTTP request body as JSON."
	{
		var raw_body_text = toString( getHttpRequestData().content );

		if ( !len( raw_body_text ) ) {
			return {};
		}

		return deserializeJson( raw_body_text );
	}


	public void function write_json_response(
		required any payload,
		numeric status_code = 200
	)
		output = "true"
		hint = "Serialize a struct/array to JSON and emit it."
	{
		cfheader( statuscode = arguments.status_code );
		cfcontent( type = "application/json; charset=utf-8", reset = true );
		writeOutput( serializeJson( arguments.payload ) );
	}


	// BINARY / BASE64URL HELPERS
	public any function generate_random_bytes( required numeric num_bytes )
		hint = "Cryptographically random bytes via java.security.SecureRandom."
	{
		// Use Java's SecureRandom directly. CF doesn't expose a built-in CSPRNG byte API.
		var secure_random = createObject( "java", "java.security.SecureRandom" );

		// Allocate a Java byte[] of the requested size, then have SecureRandom fill it.
		var random_bytes = binaryDecode( repeatString( "00", arguments.num_bytes ), "hex" );
		secure_random.nextBytes( random_bytes );

		return random_bytes;
	}


	public string function bytes_to_base64url( required any bytes )
		hint = "Convert a byte[] to a Base64URL string (no padding)."
	{
		var standard_base64 = binaryEncode( arguments.bytes, "base64" );

		return base64_to_base64url( standard_base64 );
	}


	public any function base64url_to_bytes( required string value )
		hint = "Decode a Base64URL string into a byte[]."
	{
		var standard_base64 = base64url_to_base64( arguments.value );

		return binaryDecode( standard_base64, "base64" );
	}


	public string function base64_to_base64url( required string value )
		hint = "Convert standard Base64 to URL-safe Base64 (no padding)."
	{
		var url_safe = arguments.value;
		url_safe = replace( url_safe, "+", "-", "all" );
		url_safe = replace( url_safe, "/", "_", "all" );
		url_safe = replace( url_safe, "=", "", "all" );

		return url_safe;
	}


	public string function base64url_to_base64( required string value )
		hint = "Convert URL-safe Base64 to standard Base64 (with padding)."
	{
		var standard_base64 = arguments.value;
		standard_base64 = replace( standard_base64, "-", "+", "all" );
		standard_base64 = replace( standard_base64, "_", "/", "all" );

		// Base64 strings are padded to a length divisible by 4 with "=" characters.
		var padding_length = ( 4 - ( len( standard_base64 ) mod 4 ) ) mod 4;

		if ( padding_length > 0 ) {
			standard_base64 = standard_base64 & repeatString( "=", padding_length );
		}

		return standard_base64;
	}


	public string function normalize_credential_id( required string value )
		hint = "Make sure stored/compared credential IDs are in a single canonical form (Base64URL, no padding)."
	{
		return base64_to_base64url( arguments.value );
	}


	public string function first_failed_client_data_check( required struct inspection )
		hint = "Return a message for the first failed basic clientDataJSON check, or '' if all pass."
	{
		// These are the checks the demo actually shows on screen, so it must enforce them.
		if ( !arguments.inspection.decoded_ok ) {
			return "clientDataJSON could not be decoded.";
		}
		if ( !arguments.inspection.type_matches ) {
			return "clientData.type did not match the expected WebAuthn ceremony type.";
		}
		if ( !arguments.inspection.challenge_matches ) {
			return "Challenge did not match the challenge we issued.";
		}
		// Only enforce origin when one was present in clientDataJSON (it normally is).
		if ( len( arguments.inspection.origin_seen ) && !arguments.inspection.origin_matches ) {
			return "Origin host did not match the expected Relying Party ID.";
		}
		return "";
	}


	public struct function inspect_client_data_json(
		required string client_data_json_base64url,
		required string expected_type,
		required string expected_challenge
	)
		hint = "Demo helper: decode clientDataJSON and report what we see. Basic checks only, NOT full WebAuthn verification."
	{

		var inspection_report = {
			"decoded_ok": false,
			"type_matches": false,
			"challenge_matches": false,
			"origin_seen": "",
			"origin_matches": false,
			"note": "Basic decoded checks only. NOT full WebAuthn verification (no attestation / authenticator-data / signature checks). Production must do those, or use the native ColdFusion passkey service."
		};

		try {
			var client_data_bytes = base64url_to_bytes( arguments.client_data_json_base64url );
			var client_data_text = charsetEncode( client_data_bytes, "utf-8" );
			var client_data = deserializeJson( client_data_text );

			inspection_report.decoded_ok = true;
			inspection_report.type_matches = ( structKeyExists( client_data, "type" ) && client_data.type == arguments.expected_type );
			inspection_report.challenge_matches = ( structKeyExists( client_data, "challenge" ) && client_data.challenge == arguments.expected_challenge );

			if ( structKeyExists( client_data, "origin" ) ) {
				inspection_report.origin_seen = client_data.origin;

				// The origin's host must equal our Relying Party ID. Strip scheme, then any
				// path and port, and compare. (Real WebAuthn also allows the RP ID to be a
				// registrable parent of the host; exact-match is enough for this demo.)
				var origin_host = reReplaceNoCase( client_data.origin, "^[a-z]+://", "", "one" );
				origin_host = listFirst( origin_host, "/" );
				origin_host = listFirst( origin_host, ":" );
				inspection_report.origin_matches = ( origin_host == variables.relying_party_id );
			}
		} catch ( any caught_error ) {
			inspection_report.error = caught_error.message;
		}

		return inspection_report;
	}

}
