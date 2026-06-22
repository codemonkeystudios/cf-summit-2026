
/*
	mfa.cfc
	Minimal, heavily commented MFA (multi-factor authentication) demo for ColdFusion,
	using TOTP - the six-digit codes from an authenticator app (Google Authenticator,
	Authy, Microsoft Authenticator, 1Password, ...). Written for people adding their
	first second factor. It favours clarity over completeness.

	WHAT IS TOTP? (RFC 6238)
	TOTP = Time-based One-Time Password. At enrolment the server and the user's phone
	agree on a shared SECRET. After that, both sides can independently compute the same
	short code from just two inputs:

		code = truncate( HMAC-SHA1( secret, floor( unix_time / 30 ) ) ) -> 6 digits

	Because the only moving part is the clock, a fresh code appears every 30 seconds and
	NOTHING needs to travel between phone and server. The user reads the current code off
	their app and types it in; the server computes what the code SHOULD be and compares.

	THE TWO FLOWS

	REGISTRATION (enrolment)
		1. Generate a random secret and Base32-encode it (the format apps expect).
		2. Show it to the user as a QR code / "otpauth://" link to scan into their app.
		3. Ask them to type the current 6-digit code back, and verify it. This proves
		 their app is set up correctly BEFORE you start requiring it. Only then mark
		 the user as "confirmed".

	AUTHENTICATION (the second factor at sign-in)
		After the normal first factor (password, passkey, magic link, ...), ask for the
		current 6-digit code and verify it the same way.

	WHY ALLOW A LITTLE TIME DRIFT?
	The phone's clock and the server's clock are never perfectly in sync, and the user
	needs a moment to type. So we accept the code for the current 30-second step AND one
	step either side (about 90 seconds total). More than that weakens the second factor.

	DEMO SHORTCUTS (do NOT ship these as-is)
	* Secrets live in the application scope (server memory). Production stores each user's
	 secret in a database, ENCRYPTED at rest (it is as sensitive as a password).
	* No first factor here - real MFA runs AFTER a password / passkey / magic-link login,
	 never instead of it.
	* No replay protection. Production should remember the last accepted time-step per user
	 and refuse to accept the same code twice.
	* No rate limiting or lockout, and no recovery / backup codes. Production needs all three.
*/
component
	displayname = "mfa"
	output = "false"
	hint = "Beginner-friendly TOTP multi-factor authentication demo. Not production-ready."
{

	// Standard TOTP settings. These match what authenticator apps default to, so do not
	// change them unless you also change the otpauth:// URI you hand to the app.
	variables.totp_period_seconds = 30; // a new code every 30 seconds
	variables.totp_digits = 6; // 6-digit codes
	variables.totp_allowed_drift = 1; // accept the step before / after "now" too
	variables.base32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // RFC 4648


	// LIFECYCLE
	public mfa function init() {
		// Our demo "user store". In production this is a database table, and the secret
		// column is ENCRYPTED. Each entry: { secret, confirmed, created_at }.
		if ( !structKeyExists( application, "mfa_demo_users" ) ) {
			application.mfa_demo_users = {};
		}

		return this;
	}


	// REGISTRATION - step 1: hand the user a fresh secret to scan into their app.
	public struct function start_registration(
		required string username,
		string issuer = "CF Summit 2026 Demo"
	)
		hint = "Generate a secret, store it as a pending (unconfirmed) enrolment, and return what the app needs."
	{
		var account_name = trim( arguments.username );

		if ( !len( account_name ) ) {
			return { "success": false, "message": "A username is required." };
		}

		// 20 random bytes (160 bits) is the standard secret size for HMAC-SHA1.
		var secret_base32 = base32_encode( generate_secret( 20 ) );

		// Store it as NOT YET confirmed. We only trust it once the user proves, in the
		// next step, that their app is producing matching codes.
		application.mfa_demo_users[ account_name ] = {
			"secret": secret_base32,
			"confirmed": false,
			"created_at": now()
		};

		return {
			"success": true,
			"username": account_name,
			"secret": secret_base32,
			"otpauth_uri": build_otpauth_uri( arguments.issuer, account_name, secret_base32 )
		};
	}


	// REGISTRATION - step 2: confirm the user's app is set up before we rely on it.
	public struct function confirm_registration(
		required string username,
		required string code
	)
		hint = "Verify the first code the user types from their app, then mark the enrolment confirmed."
	{
		var account_name = trim( arguments.username );

		if ( !structKeyExists( application.mfa_demo_users, account_name ) ) {
			return { "success": false, "message": "Start the setup first." };
		}

		var enrolment = application.mfa_demo_users[ account_name ];

		if ( verify_totp( enrolment.secret, arguments.code ) ) {
			application.mfa_demo_users[ account_name ].confirmed = true;
			return { "success": true, "message": "Authenticator confirmed - MFA is now enabled." };
		}

		return { "success": false, "message": "That code did not match. Check your authenticator app and try again." };
	}


	// AUTHENTICATION - verify a code at sign-in time (after the first factor).
	public struct function authenticate(
		required string username,
		required string code
	)
		hint = "Check a six-digit code for a user who has finished enrolment."
	{
		var account_name = trim( arguments.username );

		if ( !structKeyExists( application.mfa_demo_users, account_name )
			|| !application.mfa_demo_users[ account_name ].confirmed ) {
			return { "success": false, "message": "No confirmed authenticator for that user." };
		}

		var enrolment = application.mfa_demo_users[ account_name ];

		if ( verify_totp( enrolment.secret, arguments.code ) ) {
			return { "success": true, "message": "Code verified - second factor passed." };
		}

		return { "success": false, "message": "Invalid or expired code." };
	}


	// Re-read an in-progress enrolment so a page can redraw the QR after a failed confirm.
	public struct function get_setup(
		required string username,
		string issuer = "CF Summit 2026 Demo"
	)
		hint = "Return the secret + otpauth URI for an existing pending enrolment, without generating a new one."
	{
		var account_name = trim( arguments.username );

		if ( !structKeyExists( application.mfa_demo_users, account_name ) ) {
			return { "success": false };
		}

		var enrolment = application.mfa_demo_users[ account_name ];

		return {
			"success": true,
			"username": account_name,
			"secret": enrolment.secret,
			"otpauth_uri": build_otpauth_uri( arguments.issuer, account_name, enrolment.secret )
		};
	}


	// =====================================================================================
	// TOTP CORE - this is the actual RFC 6238 algorithm.
	// =====================================================================================

	private boolean function verify_totp(
		required string secret_base32,
		required string code
	)
		hint = "True if the code matches the expected code for now, or one step either side (clock drift)."
	{
		var submitted_code = trim( arguments.code );

		// Reject anything that is not exactly six digits before doing any work.
		if ( !reFind( "^\d{" & variables.totp_digits & "}$", submitted_code ) ) {
			return false;
		}

		var current_step = current_time_step();

		// Check the current step plus the allowed drift on each side.
		for ( var step_offset = -variables.totp_allowed_drift; step_offset <= variables.totp_allowed_drift; step_offset++ ) {
			var expected_code = generate_totp( arguments.secret_base32, current_step + step_offset );

			// Compare in constant time so timing cannot leak how many digits matched.
			if ( constant_time_equals( expected_code, submitted_code ) ) {
				return true;
			}
		}

		return false;
	}


	private string function generate_totp(
		required string secret_base32,
		required numeric time_step
	)
		hint = "Compute the six-digit TOTP for one 30-second time step (RFC 6238 / RFC 4226)."
	{
		var secret_bytes = base32_decode( arguments.secret_base32 );

		// The "message" HMAC signs is the time step as an 8-byte big-endian integer.
		var time_step_bytes = to_eight_byte_counter( arguments.time_step );

		// HMAC-SHA1( secret, time_step ) via Java's crypto, which handles binary cleanly.
		var secret_key_spec = createObject( "java", "javax.crypto.spec.SecretKeySpec" ).init( secret_bytes, "HmacSHA1" );
		var mac = createObject( "java", "javax.crypto.Mac" ).getInstance( "HmacSHA1" );
		mac.init( secret_key_spec );
		var hmac_bytes = mac.doFinal( time_step_bytes );

		/*
			Dynamic truncation (RFC 4226): use the low 4 bits of the LAST byte as an offset,
			then read 4 bytes starting there as a 31-bit number. (CF byte arrays are 1-based,
			and Java bytes are signed, so we mask every byte with 255 to read it unsigned.)
		*/
		var last_byte = bitAnd( hmac_bytes[ arrayLen( hmac_bytes ) ], 255 );
		var offset = bitAnd( last_byte, 15 ); // 0..15

		var byte_0 = bitAnd( hmac_bytes[ offset + 1 ], 127 ); // drop the sign bit of the top byte
		var byte_1 = bitAnd( hmac_bytes[ offset + 2 ], 255 );
		var byte_2 = bitAnd( hmac_bytes[ offset + 3 ], 255 );
		var byte_3 = bitAnd( hmac_bytes[ offset + 4 ], 255 );

		var truncated_number = bitOr(
			bitOr(
				bitOr( bitSHLN( byte_0, 24 ), bitSHLN( byte_1, 16 ) ),
				bitSHLN( byte_2, 8 )
			),
			byte_3
		);

		// Keep the low N digits and left-pad with zeros (e.g. 42 -> "000042").
		var modulo = 10 ^ variables.totp_digits;
		var otp_value = truncated_number mod modulo;

		return right( repeatString( "0", variables.totp_digits ) & otp_value, variables.totp_digits );
	}


	private numeric function current_time_step()
		hint = "The current TOTP time step: whole 30-second intervals since the Unix epoch (UTC)."
	{
		// System.currentTimeMillis() is UTC epoch milliseconds, so there are no timezone
		// surprises - the phone and the server agree on this value.
		var epoch_millis = createObject( "java", "java.lang.System" ).currentTimeMillis();

		return int( epoch_millis / 1000 / variables.totp_period_seconds );
	}


	// =====================================================================================
	// SECRET / ENCODING HELPERS
	// =====================================================================================

	private binary function generate_secret( numeric num_bytes = 20 )
		hint = "Cryptographically random bytes via java.security.SecureRandom."
	{
		// .init() explicitly calls the no-arg constructor so we get a properly seeded instance.
		var secure_random = createObject( "java", "java.security.SecureRandom" ).init();

		// Allocate a Java byte[] of the requested size, then have SecureRandom fill it.
		var random_bytes = binaryDecode( repeatString( "00", arguments.num_bytes ), "hex" );
		secure_random.nextBytes( random_bytes );

		return random_bytes;
	}


	private string function base32_encode( required binary bytes )
		hint = "Encode bytes as RFC 4648 Base32 (no padding) - the format authenticator apps expect."
	{
		var bit_buffer = 0;
		var bits_in_buffer = 0;
		var encoded_text = "";

		for ( var byte_index = 1; byte_index <= arrayLen( arguments.bytes ); byte_index++ ) {
			// Read each byte unsigned and push its 8 bits into the buffer.
			bit_buffer = bitOr( bitSHLN( bit_buffer, 8 ), bitAnd( arguments.bytes[ byte_index ], 255 ) );
			bits_in_buffer += 8;

			// Emit one Base32 character for every full 5 bits we have.
			while ( bits_in_buffer >= 5 ) {
				bits_in_buffer -= 5;
				var alphabet_index = bitAnd( bitSHRN( bit_buffer, bits_in_buffer ), 31 );
				encoded_text &= mid( variables.base32_alphabet, alphabet_index + 1, 1 );

				// Clear the bits we just emitted, so the buffer never grows past the few
				// leftover bits. Without this it would overflow on multi-byte input. (This
				// mirrors the masking the decoder already does.)
				if ( bits_in_buffer > 0 ) {
					bit_buffer = bitAnd( bit_buffer, bitSHLN( 1, bits_in_buffer ) - 1 );
				} else {
					bit_buffer = 0;
				}
			}
		}

		// Flush any leftover bits (padded with zeros on the right) into a final character.
		if ( bits_in_buffer > 0 ) {
			var final_index = bitAnd( bitSHLN( bit_buffer, 5 - bits_in_buffer ), 31 );
			encoded_text &= mid( variables.base32_alphabet, final_index + 1, 1 );
		}

		return encoded_text;
	}


	private binary function base32_decode( required string base32_text )
		hint = "Decode an RFC 4648 Base32 string back into bytes for the HMAC."
	{
		var cleaned_text = uCase( reReplace( arguments.base32_text, "[^A-Za-z2-7]", "", "all" ) );
		var bit_buffer = 0;
		var bits_in_buffer = 0;
		var hex_output = "";

		for ( var char_index = 1; char_index <= len( cleaned_text ); char_index++ ) {
			// find() returns the 1-based position in the alphabet, so subtract 1 for the value.
			var symbol_value = find( mid( cleaned_text, char_index, 1 ), variables.base32_alphabet ) - 1;

			if ( symbol_value < 0 ) {
				continue;
			}

			bit_buffer = bitOr( bitSHLN( bit_buffer, 5 ), symbol_value );
			bits_in_buffer += 5;

			// Pull out a whole byte whenever we have 8+ bits.
			if ( bits_in_buffer >= 8 ) {
				bits_in_buffer -= 8;
				var byte_value = bitAnd( bitSHRN( bit_buffer, bits_in_buffer ), 255 );
				hex_output &= right( "0" & formatBaseN( byte_value, 16 ), 2 );

				// Keep only the bits we have not consumed yet.
				bit_buffer = bitAnd( bit_buffer, bitSHLN( 1, bits_in_buffer ) - 1 );
			}
		}

		return binaryDecode( hex_output, "hex" );
	}


	// Demo verification helper: check base32_encode against the RFC 4648 test vectors and
	// confirm a generated secret round-trips. Run it from mfa/base32_selfcheck.cfm. (Public
	// only so that small page can reach the otherwise-private encoder/decoder.)
	public struct function base32_self_check()
		hint = "Check Base32 against RFC 4648 vectors and a secret round-trip. Returns { passed, results }."
	{
		var vectors = [
			{ "in": "",       "out": "" },
			{ "in": "f",      "out": "MY" },
			{ "in": "fo",     "out": "MZXQ" },
			{ "in": "foo",    "out": "MZXW6" },
			{ "in": "foob",   "out": "MZXW6YQ" },
			{ "in": "fooba",  "out": "MZXW6YTB" },
			{ "in": "foobar", "out": "MZXW6YTBOI" }
		];

		var results = [];
		var all_passed = true;

		for ( var vector in vectors ) {
			var encoded = base32_encode( charsetDecode( vector.in, "utf-8" ) );
			var passed = ( encoded == vector.out );
			all_passed = all_passed && passed;
			arrayAppend( results, { "input": "'" & vector.in & "'", "expected": vector.out, "got": encoded, "passed": passed } );
		}

		// Round-trip: encode then decode random secret bytes back to the original.
		var secret_bytes = generate_secret( 20 );
		var round_tripped = base32_decode( base32_encode( secret_bytes ) );
		var round_trip_passed = ( binaryEncode( secret_bytes, "hex" ) == binaryEncode( round_tripped, "hex" ) );
		all_passed = all_passed && round_trip_passed;
		arrayAppend( results, {
			"input": "random 20-byte secret",
			"expected": "round-trips",
			"got": ( round_trip_passed ? "round-trips" : "MISMATCH" ),
			"passed": round_trip_passed
		} );

		return { "passed": all_passed, "results": results };
	}


	private binary function to_eight_byte_counter( required numeric counter )
		hint = "Represent a counter as an 8-byte big-endian value (what HMAC signs)."
	{
		// Build a 16-character (8-byte) big-endian hex string, then decode it to bytes.
		var hex_value = formatBaseN( arguments.counter, 16 );
		hex_value = right( repeatString( "0", 16 ) & hex_value, 16 );

		return binaryDecode( hex_value, "hex" );
	}


	private string function build_otpauth_uri(
		required string issuer,
		required string account_name,
		required string secret_base32
	)
		hint = "The otpauth://totp/... URI an authenticator app reads from a QR code."
	{
		// Label is 'Issuer:account'. Both the label and the issuer parameter are URL-encoded.
		var label = urlEncodedFormat( arguments.issuer ) & ":" & urlEncodedFormat( arguments.account_name );

		return "otpauth://totp/" & label
			& "?secret=" & arguments.secret_base32
			& "&issuer=" & urlEncodedFormat( arguments.issuer )
			& "&algorithm=SHA1"
			& "&digits=" & variables.totp_digits
			& "&period=" & variables.totp_period_seconds;
	}


	private boolean function constant_time_equals(
		required string left_value,
		required string right_value
	)
		hint = "Compare two strings without short-circuiting, so response time does not leak how much matched."
	{
		if ( len( arguments.left_value ) != len( arguments.right_value ) ) {
			return false;
		}

		var difference = 0;

		for ( var position = 1; position <= len( arguments.left_value ); position++ ) {
			difference = bitOr(
				difference,
				bitXor( asc( mid( arguments.left_value, position, 1 ) ), asc( mid( arguments.right_value, position, 1 ) ) )
			);
		}

		return difference == 0;
	}

}
