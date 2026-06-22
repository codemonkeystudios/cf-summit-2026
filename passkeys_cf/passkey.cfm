<cfscript>
	/*
		passkey.cfm
		==========================================================
		A real-world, single-page example of ColdFusion's NATIVE passkey functions
		(CF 2025 Update 8), wired to buttons and the browser-side JavaScript SDK.

		Unlike a hand-rolled WebAuthn page, you do NOT write navigator.credentials.*
		here. ColdFusion auto-loads its SDK (cfpasskey.js) when you call
		PasskeyRegister() / PasskeyAuthenticate(); your JavaScript just:
			1. starts the ceremony -> CFPasskey.startRegistration() / startAuthentication()
			2. reacts to the result -> the successHandler / errorHandler callbacks below

		REQUEST FLOW ON THIS PAGE
			- No action -> show the username field + Register / Sign In buttons.
			- action=register -> call passkey.begin_registration(), emit the JS that
			 starts the registration ceremony.
			- action=authenticate -> call passkey.begin_authentication(), emit the JS that
			 starts the sign-in ceremony.
			- ?passkey_token=... -> ColdFusion redirected back here after the ceremony.
			 Call passkey.read_result() to verify and sign in.
			- action=logout -> clear the demo session.

		Needs HTTPS in production; http://localhost is the only dev exception.
	*/

	// Shared demo settings (public base URL + session-rotation helper). EDIT ../demo_config.cfm.
	include "../demo_config.cfm";

	/*
		The callback ColdFusion redirects the browser to after a ceremony must be the
		PUBLIC, browser-visible URL - passkeys are domain-bound, and behind a proxy CGI
		does not know the real host. Build it from the configured base URL. This must also
		match the Authorized origin / RP ID you configured. See ../demo_config.cfm.
	*/
	this_page_url = demo_resolved_base_url & cgi.script_name;

	// rpId and callback must both be the public, browser-visible host (they have to agree).
	passkey_service = new passkey(
		callback_url = this_page_url,
		relying_party_id = demo_relying_party_id
	);

	// What is this request asking for? Buttons POST an "action"; some steps use the URL.
	requested_action = structKeyExists( form, "action" ) ? form.action
		: ( structKeyExists( url, "action" ) ? url.action : "" );
	submitted_username = structKeyExists( form, "username" ) ? trim( form.username ) : "";

	// View state the HTML below reads. Modes: home | ceremony | result
	page_mode = "home";
	ceremony_kind = "";
	status_variant = "info";
	status_message = "";
	signed_in_user = structKeyExists( session, "passkey_user" ) ? session.passkey_user : "";

	// --- Logout ---
	if ( requested_action == "logout" ) {
		structDelete( session, "passkey_user" );
		signed_in_user = "";
	}
	// --- Callback: ColdFusion redirected back with a one-time token after a ceremony. ---
	else if ( structKeyExists( url, "passkey_token" ) && len( trim( url.passkey_token ) ) ) {
		page_mode = "result";
		ceremony_result = passkey_service.read_result( url.passkey_token );

		if ( ceremony_result.success ?: false ) {
			/*
				SECURITY: registration and authentication are NOT interchangeable. Only
				AUTHENTICATION proves the user holds the passkey, so only it may sign them in.
				REGISTRATION just enrolled a new passkey - treating that as a login would be
				an account-takeover bug. Always branch on result.action.
			*/
			result_action = ceremony_result.action ?: "";

			if ( result_action == "authentication" ) {
				// Authenticated: establish the session, and rotate the session id first
				// (session-fixation defence). See ../demo_config.cfm.
				rotate_session_if_available();
				session.passkey_user = ceremony_result.username;
				signed_in_user = ceremony_result.username;
				status_variant = "success";
				status_message = "Signed in as " & ceremony_result.username & ".";
			} else if ( result_action == "registration" ) {
				// Registered a passkey, but did NOT sign in. Tell them to sign in now.
				status_variant = "success";
				status_message = "Passkey registered for " & ceremony_result.username & ". You can now sign in with it.";
			} else {
				status_variant = "danger";
				status_message = "Unexpected result action - refusing to sign in.";
			}
		} else {
			status_variant = "danger";
			status_message = len( ceremony_result.message ?: "" )
				? ceremony_result.message
				: "The passkey ceremony did not complete.";
		}
	}
	// --- Start a REGISTRATION ceremony. ---
	else if ( requested_action == "register" ) {
		if ( !len( submitted_username ) ) {
			status_variant = "danger";
			status_message = "Please enter an email or username to register a passkey.";
		} else {
			page_mode = "ceremony";
			ceremony_kind = "register";
		}
	}
	// --- Start an AUTHENTICATION ceremony. (username is just an optional hint) ---
	else if ( requested_action == "authenticate" ) {
		page_mode = "ceremony";
		ceremony_kind = "authenticate";
	}
</cfscript>

<cfoutput>
<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>Native ColdFusion Passkey Demo &middot; CF Summit 2026</title>

		<!-- Bootstrap 5 from CDN. Production should add SRI hashes (integrity=...). -->
		<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
		<style>
			body { background: ##f7f7fb; }
			.demo-wrap { max-width: 760px; }
			code, pre { word-break: break-word; }
		</style>
	</head>

	<body>
		<div class="container demo-wrap py-4">

			<header class="mb-4">
				<h1 class="h3 mb-1">Native ColdFusion Passkey Demo</h1>
				<p class="text-muted mb-0">
					CF Summit 2026 - passkeys with the built-in <code>PasskeyRegister</code> /
					<code>PasskeyAuthenticate</code> functions (ColdFusion 2025 Update 8).
				</p>
			</header>

			<div class="alert alert-warning" role="alert">
				<strong>Demo only.</strong> Uses the development storage service
				(<code>/CFIDE/passkey/DefaultPasskey.cfc</code>) and <code>rpId = #encodeForHtml( demo_relying_party_id )#</code>
				(set in <code>demo_config.cfm</code>). Production needs HTTPS, a database-backed storage service, and a shared challenge store.
			</div>

			<!-- Status line. -->
			<cfif len( status_message )>
				<div class="alert alert-#encodeForHtmlAttribute( status_variant )#" role="status">
					#encodeForHtml( status_message )#
				</div>
			</cfif>

			<div class="card shadow-sm mb-4">
				<div class="card-body">

					<cfif page_mode eq "ceremony">

						<!---
							Configure the native ceremony SERVER-SIDE. This call loads cfpasskey.js
							and sets up the WebAuthn flow + our JS callback names. Our <script>
							below then starts it and reports progress.
						--->
						<cfif ceremony_kind eq "register">
							<cfset passkey_service.begin_registration(
								username = submitted_username,
								success_handler = "onPasskeySuccess",
								error_handler = "onPasskeyError"
							) />
						<cfelse>
							<cfset passkey_service.begin_authentication(
								username = submitted_username,
								success_handler = "onPasskeySuccess",
								error_handler = "onPasskeyError"
							) />
						</cfif>

						<h2 class="h5">Talking to your authenticator&hellip;</h2>
						<p class="text-muted">
							Your browser should be prompting you now (Touch ID, Windows Hello, a security key&hellip;).
						</p>
						<div id="passkey_status" class="alert alert-info mb-3">Starting the passkey ceremony&hellip;</div>
						<a href="#encodeForHtmlAttribute( cgi.script_name )#" class="btn btn-link p-0">Cancel</a>

						<script>
							/*
								ColdFusion already injected its passkey SDK (cfpasskey.js) above when we
								called PasskeyRegister()/PasskeyAuthenticate(). It exposes a global
								"CFPasskey" object and calls the two handlers we named in the configStruct.
							*/

							// Called by the SDK when the browser ceremony succeeds. ColdFusion will then
							// redirect us to the callback URL with ?passkey_token=..., where the SERVER
							// verifies the result and establishes the session. This is just inline UX.
							function onPasskeySuccess(credentialData, serverResult) {
								setPasskeyStatus("success", "Success - finishing up...");
							}

							// Called by the SDK on failure. errorData.code is one of
							// NOT_SUPPORTED | AUTH_FAILED | SAVE_FAILED | NOT_LOADED.
							function onPasskeyError(errorData) {
								var message = (errorData && errorData.error) ? errorData.error : "The passkey ceremony failed.";
								setPasskeyStatus("danger", message);
							}

							function setPasskeyStatus(variant, message) {
								var status_box = document.getElementById("passkey_status");
								if (!status_box) { return; }
								status_box.className = "alert alert-" + variant;
								// textContent, not innerHTML: this message can include SDK error text,
								// so we render it as plain text and never as markup.
								status_box.textContent = message;
							}

							// The SDK loads asynchronously, so wait for the ONE method this ceremony
							// needs to appear, then start. (Wait-then-start pattern is from the Adobe docs.)
							function startPasskeyWhenReady() {
								<cfif ceremony_kind eq "register">
								if (typeof CFPasskey !== "undefined" && typeof CFPasskey.startRegistration === "function") {
									CFPasskey.startRegistration();
									return;
								}
								<cfelse>
								if (typeof CFPasskey !== "undefined" && typeof CFPasskey.startAuthentication === "function") {
									CFPasskey.startAuthentication();
									return;
								}
								</cfif>
								setTimeout(startPasskeyWhenReady, 200);
							}

							document.addEventListener("DOMContentLoaded", function () {
								setTimeout(startPasskeyWhenReady, 200);
							});
						</script>

					<cfelseif page_mode eq "result" and len( signed_in_user )>

						<!-- Signed-in panel (set after the server verified the callback token). -->
						<p class="mb-2">
							<span class="badge bg-success">Signed in</span>
							<strong>#encodeForHtml( signed_in_user )#</strong>
						</p>
						<p class="text-muted">
							ColdFusion verified the ceremony server-side (challenge, origin, RP id hash,
							signature, sign counter) before we trusted this result.
						</p>
						<a href="#encodeForHtmlAttribute( cgi.script_name )#?action=logout" class="btn btn-outline-secondary">Log out</a>

					<cfelse>

						<!-- Home: username + the two buttons that POST an action back to this page. -->
						<cfif len( signed_in_user )>
							<p class="mb-3">
								<span class="badge bg-success">Signed in</span>
								<strong>#encodeForHtml( signed_in_user )#</strong>
								<a href="#encodeForHtmlAttribute( cgi.script_name )#?action=logout" class="ms-2">Log out</a>
							</p>
						</cfif>

						<form method="post" action="#encodeForHtmlAttribute( cgi.script_name )#">
							<div class="mb-3">
								<label for="username" class="form-label">Email or username</label>
								<input
									type="text"
									id="username"
									name="username"
									class="form-control"
									placeholder="alice@example.com"
									autocomplete="username">
								<div class="form-text">Required to register; an optional hint when signing in.</div>
							</div>
							<div class="d-flex flex-wrap gap-2">
								<button type="submit" name="action" value="register" class="btn btn-primary">Register Passkey</button>
								<button type="submit" name="action" value="authenticate" class="btn btn-success">Sign In With Passkey</button>
							</div>
						</form>

					</cfif>

				</div>
			</div>

			<!-- "How this works" card. -->
			<div class="card mb-4">
				<div class="card-header"><strong>How the native flow works</strong></div>
				<div class="card-body">
					<ol class="mb-0">
						<li>A button POSTs back here; the page calls <code>PasskeyRegister()</code> or <code>PasskeyAuthenticate()</code>.</li>
						<li>ColdFusion auto-loads its SDK (<code>cfpasskey.js</code>) and sets up the WebAuthn ceremony.</li>
						<li>Our JS waits for <code>CFPasskey</code>, then calls <code>CFPasskey.startRegistration()</code> / <code>startAuthentication()</code>.</li>
						<li>The SDK runs the real WebAuthn calls and invokes our <code>successHandler</code> / <code>errorHandler</code>.</li>
						<li>ColdFusion redirects back with <code>?passkey_token=...</code>; <code>PasskeyGetResult()</code> verifies it server-side.</li>
						<li>We branch on <code>result.action</code> and start the session. <strong>Never</strong> treat registration as authentication.</li>
					</ol>
				</div>
			</div>

			<footer class="text-center text-muted small mt-5">
				<div>CF Summit 2026 - Native passkey demo. Educational use only.</div>
			</footer>

		</div>
	</body>
</html>
</cfoutput>
