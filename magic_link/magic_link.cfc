
/*
	magic_link.cfc
	Minimal, heavily commented "magic link" sign-in demo for ColdFusion.
	Written for people building their first magic-link flow. It favours
	clarity over completeness.

	WHAT IS A MAGIC LINK?
	Instead of a password, the user just types their email address. You email
	them a one-time link that contains a long random token. Clicking the link
	proves they control that inbox, so you sign them in. There is no password to
	store, leak, phish, or forget.

	THE FLOW (5 steps)
	1.	The user submits their email address.
	2.	You generate a long, RANDOM, single-use token.
	3.	You store only a HASH of the token, together with an expiry time and a
		"used yet?" flag. (You never store the raw token.)
	4.	You email the user a link that contains the RAW token, e.g.
		https://example.com/login?token=<raw token>
	5.	When they click it, you hash the incoming token, look it up, confirm it
		has not expired and has not already been used, mark it used, and sign the
		user in.

	WHY STORE ONLY A HASH OF THE TOKEN?
	The token is password-equivalent: anyone holding it can sign in as that user.
	If your token store (or a database backup) ever leaks and you saved raw
	tokens, every live link is compromised. Storing only a one-way SHA-256 hash
	means a leaked store is useless - you cannot turn a hash back into a working
	link. On each click you simply hash the incoming token and compare.

	DEMO SHORTCUTS (do NOT ship these as-is)

	* Tokens live in the application scope (server memory). Production uses a
	database table so links survive a restart and work across multiple servers.
	* There is no real user-account lookup; any email address "works". Production
	looks the user up and ALWAYS returns the same "check your email" response
	whether or not the account exists, so attackers cannot use the form to
	discover which email addresses are registered (email enumeration).
	* The link is shown on screen instead of emailed, so the demo runs without a
	mail server. The real cfmail version is included at the bottom of this file.
	* No rate limiting. Production limits requests per email and per IP so the
	feature cannot be abused to spam someone's inbox.
*/
component
	displayname = "magic_link"
	output = "false"
	hint = "Beginner-friendly magic link (passwordless email sign-in) demo. Not production-ready."
{

	// How long a link stays valid. Keep this short: long enough for the user to
	// switch to their email app and click, short enough to limit the risk window.
	variables.token_lifetime_minutes = 15;


	// LIFECYCLE
	public magic_link function init() {
		// Our demo "token store". In production this is a database table - one row
		// per issued link - NOT a struct in server memory.
		if ( !structKeyExists( application, "magic_link_tokens" ) ) {
			application.magic_link_tokens = {};
		}

		return this;
	}


	// STEPS 2-4: issue a one-time link for an email address.
	public struct function request_magic_link(
		required string email_address,
		required string base_url
	)
		hint = "Generate a one-time token, store its hash, and build the link the user will click."
	{
		var normalized_email = lCase( trim( arguments.email_address ) );

		// A light shape check so the demo gives useful feedback. Production would
		// also look up a real user account at this point (see notes at the top).
		if ( !len( normalized_email ) || !isValid( "email", normalized_email ) ) {
			return { "success": false, "message": "Please enter a valid email address." };
		}

		// Opportunistically sweep out expired tokens so the in-memory store does not grow
		// forever during a long workshop. This is cheap and self-throttling (see below).
		cleanup_expired_tokens();

		// STEP 2: a long, unguessable, single-use token.
		var raw_token = generate_token();

		// STEP 3: store ONLY the hash, plus when it expires and whether it has
		// been used. We key the store by the hash so we can find this record later
		// without ever keeping the raw token anywhere on the server.
		var token_hash = hash_token( raw_token );

		application.magic_link_tokens[ token_hash ] = {
			"email_address": normalized_email,
			"expires_at": dateAdd( "n", variables.token_lifetime_minutes, now() ),
			"consumed": false
		};

		// STEP 4: build the link the user will click. The RAW token (never the
		// hash) goes in the URL - the raw token is the secret the email carries.
		var magic_link_url = build_magic_link_url( arguments.base_url, raw_token );

		// In a real app you would EMAIL this link now and simply tell the user
		// "check your inbox" (see send_magic_link_email below). For the demo we
		// hand the link back so the example page can display it on screen.
		return {
			"success": true,
			"email_address": normalized_email,
			"magic_link_url": magic_link_url,
			"expires_in_minutes": variables.token_lifetime_minutes
		};
	}


	// STEP 5: consume a token when the user clicks the link.
	public struct function consume_magic_link( required string token )
		hint = "Validate an incoming token (known, not expired, not already used), then report who signed in."
	{
		var raw_token = trim( arguments.token );

		if ( !len( raw_token ) ) {
			return { "success": false, "message": "Missing token." };
		}

		// Hash the incoming token the SAME way we did when issuing it.
		var token_hash = hash_token( raw_token );

		/*
			Atomicity: look up, check, and mark-consumed inside one exclusive lock keyed by
			this token. Without it, two simultaneous clicks of the same link could both pass
			the "consumed" check before either writes it back, and the link would work twice.
			Production should instead do this as one atomic database statement, e.g.
			UPDATE ... SET consumed = true WHERE token_hash = ? AND consumed = false, and act
			on whether a row was actually updated.
		*/
		var consume_outcome = { "success": false, "message": "This link is invalid." };

		lock name="magic_link_token_#token_hash#" type="exclusive" timeout="5" {
			if ( !structKeyExists( application.magic_link_tokens, token_hash ) ) {
				consume_outcome = { "success": false, "message": "This link is invalid." };
			} else {
				var stored_token = application.magic_link_tokens[ token_hash ];

				// Single use: a link that was already clicked must not work again.
				if ( stored_token.consumed ) {
					consume_outcome = { "success": false, "message": "This link has already been used." };
				}
				// Expiry: a link older than its lifetime must not work.
				else if ( dateCompare( now(), stored_token.expires_at ) >= 0 ) {
					structDelete( application.magic_link_tokens, token_hash );
					consume_outcome = { "success": false, "message": "This link has expired. Please request a new one." };
				}
				// Valid! Mark it used inside the lock so the same link cannot be replayed.
				else {
					application.magic_link_tokens[ token_hash ].consumed = true;
					consume_outcome = { "success": true, "email_address": stored_token.email_address };
				}
			}
		}

		// The caller now knows which email address was just proven (on success), and can
		// start a logged-in session for that user.
		return consume_outcome;
	}


	// TOKEN HELPERS

	private string function generate_token()
		hint = "A long, cryptographically random, URL-safe token."
	{
		// generateSecretKey gives us 256 bits (32 bytes) of strong randomness as a
		// Base64 string. Base64 can contain +, / and = which are awkward in URLs,
		// so we swap them for URL-safe characters. The result is unguessable.
		var random_base64 = generateSecretKey( "AES", 256 );

		var url_safe_token = random_base64;
		url_safe_token = replace( url_safe_token, "+", "-", "all" );
		url_safe_token = replace( url_safe_token, "/", "_", "all" );
		url_safe_token = replace( url_safe_token, "=", "", "all" );

		return url_safe_token;
	}


	private string function hash_token( required string raw_token )
		hint = "One-way SHA-256 hash. The same token always hashes to the same value, so we can look it up."
	{
		return hash( arguments.raw_token, "SHA-256" );
	}


	private void function cleanup_expired_tokens()
		hint = "Drop expired tokens from the in-memory store, at most once every few minutes."
	{
		// Self-throttle: only sweep if we have not swept in the last few minutes, so this
		// stays off the hot path and most requests do no extra work. Production would lean
		// on a TTL store or an indexed scheduled DELETE instead of sweeping in-process.
		var cleanup_interval_minutes = 5;
		var last_cleanup = application.magic_link_last_cleanup ?: "";

		if ( isDate( last_cleanup ) && dateDiff( "n", last_cleanup, now() ) < cleanup_interval_minutes ) {
			return;
		}

		// Set the marker first so concurrent callers skip straight past (a double sweep
		// would only be wasted work, never incorrect).
		application.magic_link_last_cleanup = now();

		// Iterate a snapshot of the keys so deleting as we go cannot disturb the loop.
		for ( var token_hash in structKeyArray( application.magic_link_tokens ) ) {
			if ( structKeyExists( application.magic_link_tokens, token_hash )
				&& dateCompare( now(), application.magic_link_tokens[ token_hash ].expires_at ) >= 0 ) {
				structDelete( application.magic_link_tokens, token_hash );
			}
		}
	}


	private string function build_magic_link_url(
		required string base_url,
		required string raw_token
	)
		hint = "Attach the raw token to the sign-in URL as a query-string parameter."
	{
		// Trim any trailing slash so we never produce a double slash in the link.
		var clean_base_url = reReplace( arguments.base_url, "/$", "", "one" );

		return clean_base_url & "?token=" & urlEncodedFormat( arguments.raw_token );
	}


	// OPTIONAL: how you would actually EMAIL the link.
	// The demo page shows the link on screen instead of sending it, so this method
	// is not called there - but this is the shape of the real thing. It needs a
	// mail server configured in the ColdFusion Administrator (or Application.cfc).
	public void function send_magic_link_email(
		required string email_address,
		required string magic_link_url
	)
		hint = "Email the magic link with cfmail. Requires a configured mail server."
	{
		cfmail(
			to = arguments.email_address,
			from = "no-reply@example.com",
			subject = "Your sign-in link",
			type = "html"
		) {
			writeOutput( '<p>Click the link below to sign in. It expires in ' & variables.token_lifetime_minutes & ' minutes and can only be used once.</p>' );
			// HTML-attribute-encode the URL before dropping it into an href. The token is
			// server-generated here, but encoding any value you print into markup is the
			// habit to teach - it is what stops attribute injection.
			writeOutput( '<p><a href="' & encodeForHtmlAttribute( arguments.magic_link_url ) & '">Sign in</a></p>' );
			writeOutput( '<p>If you did not request this, you can safely ignore this email.</p>' );
		}
	}

}
