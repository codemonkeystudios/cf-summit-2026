<cfscript>
	// Shared demo settings (the Relying Party ID lives in ../demo_config.cfm).
	include "../demo_config.cfm";

	/*
		Single instance, application-cached, built under a lock so two first-hit requests
		cannot both create it (double-checked locking). The Relying Party ID is taken from
		demo_config.cfm - WebAuthn is domain-bound, so set it to match the host the browser
		sees. NOTE: this instance is cached, so after changing demo_relying_party_id you
		must reload the application scope (restart CF or clear the scope) for it to apply.
	*/
	if ( !structKeyExists( application, "passkey" ) ) {
		lock scope="application" type="exclusive" timeout="5" {
			if ( !structKeyExists( application, "passkey" ) ) {
				application.passkey = new passkey( relying_party_id = demo_relying_party_id );
			}
		}
	}

	/*
		JSON ENDPOINT ROUTER
		If url.action is set, we treat this request as an API call, return JSON, and abort before rendering HTML.
	*/
	if ( structKeyExists( url, "action" ) && len( trim( url.action ) ) ) {
		try {
			switch ( url.action ) {
				case "start_registration":
					variables.request_body = application.passkey.read_json_request_body();

					if ( !structKeyExists( variables.request_body, "username" ) || !len( trim( variables.request_body.username ) ) ) {
						application.passkey.write_json_response( { "error": "username is required" }, 400 );
					} else {
						variables.options = application.passkey.start_registration( variables.request_body.username );
						application.passkey.write_json_response( variables.options );
					}

					break;

				case "finish_registration":
					variables.request_body = application.passkey.read_json_request_body();
					variables.result = application.passkey.finish_registration( variables.request_body );
					application.passkey.write_json_response( variables.result );

					break;

				case "start_authentication":
					variables.request_body = application.passkey.read_json_request_body();

					if ( !structKeyExists( variables.request_body, "username" ) || !len( trim( variables.request_body.username ) ) ) {
						application.passkey.write_json_response( { "error": "username is required" }, 400 );
					} else {
						variables.options = application.passkey.start_authentication( variables.request_body.username );
						application.passkey.write_json_response( variables.options );
					}

					break;

				case "finish_authentication":
					variables.request_body = application.passkey.read_json_request_body();
					variables.result = application.passkey.finish_authentication( variables.request_body );
					application.passkey.write_json_response( variables.result );

					break;

				case "logout":
					variables.result = application.passkey.logout();
					application.passkey.write_json_response( variables.result );

					break;

				case "current_user":
					variables.result = application.passkey.get_current_user();
					application.passkey.write_json_response( variables.result );

					break;

				default:
					application.passkey.write_json_response( { "error": "Unknown action: " & url.action }, 400 );
			}
		} catch ( any cfcatch ) {
			application.passkey.write_json_response( {
				"error": cfcatch.message,
				"detail": cfcatch.detail,
				"type": cfcatch.type
			}, 500 );
		}

		abort;
	}
</cfscript>

<!--- HTML DEMO PAGE --->
<cfoutput>
<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>ColdFusion Passkey Demo &middot; CF Summit 2026</title>

	<!-- Bootstrap 5 from CDN. Production should add SRI hashes (integrity=...). -->
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
	<style>
		body { background: ##f7f7fb; }
		.demo-wrap { max-width: 760px; }
		pre { white-space: pre-wrap; word-break: break-word; }
	</style>
</head>
<body>

<div class="container demo-wrap py-4">

	<header class="mb-4">
		<h1 class="h3 mb-1">ColdFusion Passkey Demo</h1>
		<p class="text-muted mb-0">
			A teaching example for CF Summit 2026 - WebAuthn / passkeys in Adobe ColdFusion.
		</p>
	</header>

	<!-- Production warning callout. -->
	<div class="alert alert-warning" role="alert">
		<strong>Demo only.</strong> This page intentionally simplifies production WebAuthn validation.
		It is meant to teach the <em>shape</em> of the protocol, not to be deployed as-is. See the
		comments in <code>passkey.cfc</code> for the full list of checks a production system must perform.
	</div>

	<!-- Main interaction card. -->
	<div class="card shadow-sm mb-4">
		<div class="card-body">

			<div class="mb-3">
				<label for="passkey_username" class="form-label">Email or username</label>
				<input
					type="text"
					id="passkey_username"
					class="form-control"
					placeholder="alice@example.com"
					autocomplete="username">
				<div class="form-text">
					Used as the WebAuthn user identifier in this demo.
				</div>
			</div>

			<div class="d-flex flex-wrap gap-2 mb-3">
				<button id="passkey_register_btn" type="button" class="btn btn-primary">Register Passkey</button>
				<button id="passkey_signin_btn" type="button" class="btn btn-success">Sign In With Passkey</button>
				<button id="passkey_logout_btn" type="button" class="btn btn-outline-secondary">Logout</button>
			</div>

			<div id="passkey_status" class="alert d-none" role="status"></div>

			<div class="mt-3">
				<small class="text-muted">Current session:</small>
				<div id="passkey_current_user" class="mt-1">
					<span class="badge bg-secondary">Not signed in</span>
				</div>
			</div>

		</div>
	</div>

	<!-- "How this works" card. -->
	<div class="card mb-4">
		<div class="card-header"><strong>How the demo flow works</strong></div>
		<div class="card-body">
			<ol class="mb-0">
				<li>You enter an email or username.</li>
				<li>The browser asks <code>passkey_example.cfm?action=start_registration</code> for a fresh challenge and creation options.</li>
				<li><code>passkey.js</code> converts Base64URL fields into ArrayBuffers and calls <code>navigator.credentials.create()</code>.</li>
				<li>The browser/authenticator (Touch ID, Windows Hello, security key, ...) creates a key pair and returns an attestation.</li>
				<li><code>passkey.js</code> Base64URL-encodes the response and POSTs it to <code>?action=finish_registration</code>.</li>
				<li>Sign-in repeats the flow with <code>navigator.credentials.get()</code>; the server (in production) verifies the assertion signature.</li>
			</ol>
		</div>
	</div>

	<!-- Caveats card. -->
	<div class="card mb-4">
		<div class="card-header"><strong>Important caveats</strong></div>
		<div class="card-body">
			<ul class="mb-0">
				<li>Passkeys require <strong>HTTPS</strong>. The only exception is <code>http://localhost</code> during development.</li>
				<li>Browser and platform support varies. Always feature-detect <code>window.PublicKeyCredential</code>.</li>
				<li>This demo simplifies production-grade WebAuthn validation - signatures are <em>not</em> verified server-side here.</li>
				<li>Production apps must persist credentials in a database and perform full cryptographic signature verification.</li>
			</ul>
		</div>
	</div>

	<!-- Debug accordion. -->
	<div class="accordion mb-4" id="passkey_debug_acc">
		<div class="accordion-item">
			<h2 class="accordion-header">
				<button class="accordion-button collapsed" type="button"
					data-bs-toggle="collapse" data-bs-target="##passkey_debug_panel">
					Debug panel
				</button>
			</h2>
			<div id="passkey_debug_panel" class="accordion-collapse collapse" data-bs-parent="##passkey_debug_acc">
				<div class="accordion-body">
					<p class="mb-2">
						Open your browser devtools console for verbose logs. The helpers are exposed
						as <code>window.passkey_demo</code> for live inspection during the talk.
					</p>
					<p class="mb-0">
						Server-side, demo credentials live in <code>application.passkey_demo_users</code>
						and the active challenge lives in <code>session.passkey_challenge</code>.
						Restart ColdFusion (or clear the application scope) to reset.
					</p>
				</div>
			</div>
		</div>
	</div>

	<footer class="text-center text-muted small mt-5">
		<div>CF Summit 2026 - Passkey / WebAuthn demo. Educational use only.</div>
	</footer>

</div>

<!-- Bootstrap 5 JS bundle (needed for the accordion). -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

<!-- The demo's JavaScript. -->
<script src="passkey.js"></script>

</body>
</html>
</cfoutput>
