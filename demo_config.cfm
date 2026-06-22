<cfscript>
	/*
		demo_config.cfm
		Shared settings for the CF Summit 2026 auth demos. Each demo page pulls this in
		with include "../demo_config.cfm"; so you change these values in ONE place.

		WHY A PUBLIC BASE URL MATTERS
		Passkeys are bound to a domain, and emailed magic links are clicked from an
		external mail app - so both need the PUBLIC, browser-visible origin, NOT whatever
		ColdFusion guesses from CGI behind a reverse proxy (ngrok, nginx, Apache, an AWS
		ALB, Cloudflare, ...). Set these to what your audience's browser actually sees.
	*/

	// 1) The public origin the BROWSER sees (scheme + host [+ port]); no trailing slash.
	// Examples: "https://abc123.ngrok-free.app" or "https://demo.example.com"
	// Leave BLANK to fall back to CGI - fine for a plain http://localhost demo.
	demo_public_base_url = "";

	// 2) The passkey Relying Party ID: the BARE host of the URL above (no scheme, no port).
	// Examples: "abc123.ngrok-free.app", "demo.example.com". Use "localhost" locally.
	// WebAuthn is domain-bound: this MUST match the browser-visible host exactly.
	demo_relying_party_id = "localhost";


	// Derived: a usable base URL. Explicit config wins; CGI is a LOCAL-ONLY fallback. ---
	if ( len( trim( demo_public_base_url ) ) ) {
		demo_resolved_base_url = reReplace( trim( demo_public_base_url ), "/$", "", "one" );
	} else {
		// Local-demo fallback only - do not trust CGI behind a proxy.
		demo_fallback_scheme = ( ( cgi.https ?: "" ) == "on" || cgi.server_port == 443 ) ? "https" : "http";
		demo_fallback_port = listFind( "80,443", cgi.server_port ) ? "" : ( ":" & cgi.server_port );
		demo_resolved_base_url = demo_fallback_scheme & "://" & cgi.server_name & demo_fallback_port;
	}


	/**
	 * Rotate the session id after a successful login, to limit session-fixation risk.
	 * sessionRotate() exists on modern engines; this is a safe no-op where it does not.
	 */
	function rotate_session_if_available() {
		try {
			sessionRotate();
		} catch ( any rotation_error ) {
			// Demo fallback for runtimes without sessionRotate(). Production should run on
			// an engine that supports it (or otherwise issue a fresh session id at login).
		}
	}
</cfscript>
