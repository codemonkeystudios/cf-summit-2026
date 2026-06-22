
/*
	passkey.cfc (passkeys_cf)
	==========================================================
	Minimal, heavily commented example of using ColdFusion's NATIVE passkey
	(WebAuthn / FIDO2) functions, introduced in Adobe ColdFusion 2025 Update 8.

	Contrast this with ../passkeys_native/passkey.cfc, which hand-rolls the entire
	WebAuthn ceremony (random challenges, Base64URL plumbing, COSE public keys,
	signature verification, sign counters). Here, ColdFusion does ALL of that for
	you behind just three built-in functions:

		PasskeyRegister( userStruct, configStruct ) -> start a registration
		PasskeyAuthenticate( userStruct, configStruct ) -> start a sign-in
		PasskeyGetResult( token ) -> read the outcome

	SOURCE OF TRUTH (verify exact signatures / arguments here):
	https://guides.adobe.com/coldfusion/en/docs/introduction-to-coldfusion/__references__/passkeys-in-coldfusion.html


	HOW THE NATIVE FLOW WORKS (big picture)
		1.	Your page calls PasskeyRegister() or PasskeyAuthenticate().
			ColdFusion emits the browser-side JavaScript that runs the WebAuthn
			ceremony (navigator.credentials.create() / .get()), generates and tracks
			the challenge, and handles CSRF protection for you.
		2.	The authenticator (Touch ID, Windows Hello, a security key, ...) does its
			part and hands the result back to ColdFusion.
		3.	ColdFusion stores (registration) or looks up (authentication) the
			credential using the configured "service" storage CFC (see below), and on
			sign-in verifies the assertion signature for you.
		4.	ColdFusion redirects the browser to your "redirectUrl" with a one-time
			"passkey_token" on the query string.
		5.	Your callback page calls PasskeyGetResult( token ) to read the result.

	STORAGE SERVICE ("service")
	The native functions persist / look up credentials through a storage CFC:
		- /CFIDE/passkey/DefaultPasskey.cfc - file based, DEVELOPMENT ONLY.
		- /CFIDE/passkey/DatabasePasskey.cfc - database backed, for production
		 and multi-server setups. Needs a datasource (configured in the
		 ColdFusion Administrator under Security > Passkey, or in Application.cfc).
	You may also point "service" at your own CFC that implements the same storage
	interface.

	CHALLENGE STORE (ColdFusion Administrator > Security > Passkey)
	Challenges are held server-side between the start and finish of a ceremony:
		- challenge store: "memory" (single server), "ehcache" or "servercache"
		 (clustered). In a load-balanced cluster, "memory" will NOT share the
		 challenge across JVMs, so a ceremony that starts on node A and finishes
		 on node B will fail. Use a shared store there.
		- challenge TTL: lifetime in SECONDS, allowed range ~30-600 (default 60).

	REQUIREMENTS
	- ColdFusion 2025 Update 8 or later.
	- HTTPS in production. http://localhost is the only allowed exception for dev.
	- A matching Relying Party id (rpId) -> the domain the browser actually sees.

	TYPICAL USAGE FROM A .cfm PAGE
		passkey = new passkey();

		// On the "register" button submit:
		passkey.begin_registration( form.username );

		// On the "sign in" button submit:
		passkey.begin_authentication( form.username );

		// On passkey_callback.cfm (the redirectUrl), read what happened. Branch on
		// result.action - registration and authentication are NOT interchangeable, and
		// only AUTHENTICATION may sign the user in:
		if ( structKeyExists( url, "passkey_token" ) ) {
			result = passkey.read_result( url.passkey_token );
			if ( result.success && result.action == "authentication" ) {
				// Authentication proved they hold the passkey -> sign them in.
				session.user = result.username;
			} else if ( result.success && result.action == "registration" ) {
				// Passkey registered. Do NOT sign in here - ask the user to sign in with it.
			}
		}
*/
component
	displayname = "passkey"
	output = "false"
	hint = "Minimal wrapper around ColdFusion's native passkey (WebAuthn) functions. CF Summit 2026 demo."
{

	// LIFECYCLE
	public passkey function init(
		string relying_party_id = "",
		string relying_party_name = "ColdFusion Passkey Demo",
		string storage_service = "/CFIDE/passkey/DefaultPasskey.cfc",
		string callback_url = "passkey_callback.cfm"
	)
		hint = "Stash the handful of settings every ceremony needs. Override these per environment."
	{
		/*
			The Relying Party is YOUR site. rpId must match the domain the browser
			sees: "example.com" in production, "localhost" (or cgi.server_name) in
			development. If the caller did not pass one, fall back to the host name
			of the current request.
		*/
		variables.relying_party_id = len( arguments.relying_party_id )
			? arguments.relying_party_id
			: cgi.server_name;

		variables.relying_party_name = arguments.relying_party_name;

		/*
			Which storage CFC ColdFusion should use to save / find credentials.
			DefaultPasskey.cfc is fine for a demo; use DatabasePasskey.cfc (or your
			own service CFC) for anything real.
		*/
		variables.storage_service = arguments.storage_service;

		// The page ColdFusion redirects the browser back to once the ceremony finishes. It receives a one-time token as url.passkey_token.
		variables.callback_url = arguments.callback_url;

		return this;
	}


	// REGISTRATION - create a brand new passkey for a user
	public void function begin_registration(
		required string username,
		string display_name = "",
		string success_handler = "",
		string error_handler = ""
	)
		output = "true"
		hint = "Start native passkey registration. ColdFusion drives the browser ceremony from here."
	{
		// userStruct: describes WHO we are registering. "name" is the only field you must supply; ColdFusion generates / fills in the rest (user id, etc).
		var user_details = {
			"name": arguments.username,
			"displayName": len( arguments.display_name ) ? arguments.display_name : arguments.username,
			"rpId": variables.relying_party_id,
			"rpName": variables.relying_party_name,
			// "preferred" asks for biometrics/PIN when available without hard-failing authenticators that cannot do user verification.
			"userVerification": "preferred"
		};

		// configStruct: tells ColdFusion where to store the new credential and where to send the browser when the ceremony is done.
		var registration_config = {
			"service": variables.storage_service,
			"redirectUrl": variables.callback_url
		};

		/*
			Optional: names of JavaScript functions ColdFusion's passkey SDK will call
			in the browser when the ceremony finishes, for inline UX feedback. CF still
			redirects to redirectUrl afterwards, where you DURABLY establish the session.
				successHandler( credentialData, serverResult )
				errorHandler( errorData )  ->  errorData.error, errorData.code
		*/
		if ( len( arguments.success_handler ) ) {
			registration_config[ "successHandler" ] = arguments.success_handler;
		}
		if ( len( arguments.error_handler ) ) {
			registration_config[ "errorHandler" ] = arguments.error_handler;
		}

		/*
			One call does it all: ColdFusion emits the WebAuthn JavaScript, runs
			navigator.credentials.create(), persists the credential through the
			storage service, then redirects to redirectUrl with a passkey_token.
		*/
		PasskeyRegister( user_details, registration_config );
	}


	// AUTHENTICATION - sign in with an existing passkey
	public void function begin_authentication(
		string username = "",
		string success_handler = "",
		string error_handler = ""
	)
		output = "true"
		hint = "Start native passkey sign-in. Username is just a hint; passkeys can be usernameless."
	{
		/*
			userStruct: for sign-in ColdFusion mainly needs the Relying Party id so
			it can locate the right credentials. A username is an optional hint -
			leave it off entirely to support 'usernameless' / discoverable sign-in.
		*/
		var authentication_request = {
			"rpId": variables.relying_party_id,
			"userVerification": "preferred"
		};

		if ( len( trim( arguments.username ) ) ) {
			authentication_request[ "username" ] = arguments.username;
		}

		var authentication_config = {
			"service": variables.storage_service,
			"redirectUrl": variables.callback_url
		};

		// Same optional JavaScript callbacks as registration (see begin_registration).
		if ( len( arguments.success_handler ) ) {
			authentication_config[ "successHandler" ] = arguments.success_handler;
		}
		if ( len( arguments.error_handler ) ) {
			authentication_config[ "errorHandler" ] = arguments.error_handler;
		}

		/*
			ColdFusion emits the WebAuthn JavaScript, runs navigator.credentials.get(),
			verifies the assertion signature against the stored credential, then
			redirects to redirectUrl with a passkey_token.
		*/
		PasskeyAuthenticate( authentication_request, authentication_config );
	}


	// CALLBACK - read the outcome after ColdFusion redirects back
	public struct function read_result(
		required string passkey_token
	)
		hint = "Exchange the one-time token ColdFusion placed on the callback URL for the ceremony result."
	{
		/*
			PasskeyGetResult turns the one-time token into a result struct:
			success - boolean; did the ceremony succeed?
			action - "registration" or "authentication"
			username - the user the ceremony was for
			credentialId - id of the passkey that was created / used
			userId - the stored user identifier
			message - error message when success is false

			By the time you read this, ColdFusion has already done the heavy crypto:
			challenge match, origin check, RP id hash, signature verification, and
			the sign-counter / clone check. That is the whole point of going native.
		*/
		return PasskeyGetResult( arguments.passkey_token );
	}

}
