<cfscript>
	// One shared service instance for the whole application, created under a lock so two
	// first-hit requests cannot both build it (double-checked locking).
	if ( !structKeyExists( application, "mfa" ) ) {
		lock scope="application" type="exclusive" timeout="5" {
			if ( !structKeyExists( application, "mfa" ) ) {
				application.mfa = new mfa();
			}
		}
	}

	// Read the submitted form values once.
	requested_action = structKeyExists( form, "action" ) ? form.action : "";
	submitted_username = structKeyExists( form, "username" ) ? trim( form.username ) : "";
	submitted_code = structKeyExists( form, "code" ) ? trim( form.code ) : "";

	// View state the HTML below reads.  Modes: home | setup
	page_mode = "home";
	status_variant = "info";
	status_message = "";
	enrolment = {};

	// --- Registration step 1: generate a secret and show the QR / manual key. ---
	if ( requested_action == "start" ) {
		start_result = application.mfa.start_registration( submitted_username );

		if ( start_result.success ) {
			page_mode = "setup";
			enrolment = start_result;
		} else {
			status_variant = "danger";
			status_message = start_result.message;
		}
	}
	// --- Registration step 2: confirm the first code the user types. ---
	else if ( requested_action == "confirm" ) {
		confirm_result = application.mfa.confirm_registration( submitted_username, submitted_code );

		if ( confirm_result.success ) {
			status_variant = "success";
			status_message = confirm_result.message & " You can now sign in with a code below.";
		} else {
			// Re-show the setup screen (with the same QR) so the user can try again.
			existing_setup = application.mfa.get_setup( submitted_username );
			status_variant = "danger";
			status_message = confirm_result.message;

			if ( existing_setup.success ) {
				page_mode = "setup";
				enrolment = existing_setup;
			}
		}
	}
	// --- Authentication: verify a code for an already-enrolled user. ---
	else if ( requested_action == "verify" ) {
		verify_result = application.mfa.authenticate( submitted_username, submitted_code );
		status_variant = verify_result.success ? "success" : "danger";
		status_message = verify_result.message;
	}
</cfscript>
<cfoutput>
<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>MFA (TOTP) Demo &middot; CF Summit 2026</title>

	<!-- Bootstrap 5 from CDN. Production should add SRI hashes (integrity=...). -->
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
	<style>
		body { background: ##f7f7fb; }
		.demo-wrap { max-width: 760px; }
		.secret-key { font-family: monospace; letter-spacing: 2px; word-break: break-all; }
		##mfa_qr { display: inline-block; padding: 12px; background: ##fff; border: 1px solid ##e6e8ee; border-radius: 8px; }
	</style>
</head>
<body>

<div class="container demo-wrap py-4">

	<header class="mb-4">
		<h1 class="h3 mb-1">Multi-Factor Authentication Demo</h1>
		<p class="text-muted mb-0">
			CF Summit 2026 - TOTP (authenticator-app) second factor in ColdFusion.
		</p>
	</header>

	<div class="alert alert-warning" role="alert">
		<strong>Demo only.</strong> Secrets are kept in server memory and there is no first
		factor. Real MFA runs <em>after</em> a password / passkey / magic-link login, and
		stores each secret encrypted in a database. See <code>mfa.cfc</code> for the full list.
	</div>

	<!-- Status line. -->
	<cfif len( status_message )>
		<div class="alert alert-#encodeForHtmlAttribute( status_variant )#" role="status">
			#encodeForHtml( status_message )#
		</div>
	</cfif>

	<cfif page_mode eq "setup">

		<!-- REGISTRATION STEP 2: scan, then confirm. -->
		<div class="card shadow-sm mb-4">
			<div class="card-header"><strong>Set up your authenticator</strong></div>
			<div class="card-body">

				<p>Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password&hellip;):</p>

				<div class="text-center mb-3">
					<div id="mfa_qr"></div>
				</div>

				<p class="mb-1">Can't scan? Enter this key manually instead:</p>
				<p class="secret-key mb-3">#encodeForHtml( enrolment.secret )#</p>

				<hr>

				<p>Then type the current 6-digit code from the app to finish setup:</p>
				<form method="post" action="#encodeForHtmlAttribute( cgi.script_name )#" class="row g-2">
					<input type="hidden" name="username" value="#encodeForHtmlAttribute( enrolment.username )#">
					<input type="hidden" name="action" value="confirm">
					<div class="col-auto">
						<input
							type="text"
							name="code"
							class="form-control"
							inputmode="numeric"
							autocomplete="one-time-code"
							pattern="\d{6}"
							maxlength="6"
							placeholder="123456"
							required>
					</div>
					<div class="col-auto">
						<button type="submit" class="btn btn-primary">Confirm</button>
					</div>
					<div class="col-12">
						<a href="#encodeForHtmlAttribute( cgi.script_name )#" class="btn btn-link p-0">Start over</a>
					</div>
				</form>

			</div>
		</div>

		<!-- Render the QR client-side so the secret never leaves this page/server. -->
		<script src="https://cdn.jsdelivr.net/gh/davidshimjs/qrcodejs/qrcode.min.js"></script>
		<script>
			(function () {
				var qr_target = document.getElementById("mfa_qr");
				if (qr_target && typeof QRCode !== "undefined") {
					new QRCode(qr_target, {
						text: "#encodeForJavaScript( enrolment.otpauth_uri )#",
						width: 180,
						height: 180
					});
				}
			})();
		</script>

	<cfelse>

		<!-- HOME: the two flows side by side. -->
		<div class="card shadow-sm mb-4">
			<div class="card-header"><strong>1. Register an authenticator</strong></div>
			<div class="card-body">
				<p class="text-muted">Generate a secret and pair it with your phone's authenticator app.</p>
				<form method="post" action="#encodeForHtmlAttribute( cgi.script_name )#" class="row g-2">
					<input type="hidden" name="action" value="start">
					<div class="col-auto">
						<input
							type="text"
							name="username"
							class="form-control"
							placeholder="alice@example.com"
							autocomplete="username"
							required>
					</div>
					<div class="col-auto">
						<button type="submit" class="btn btn-primary">Start setup</button>
					</div>
				</form>
			</div>
		</div>

		<div class="card shadow-sm mb-4">
			<div class="card-header"><strong>2. Sign in with a code</strong></div>
			<div class="card-body">
				<p class="text-muted">Once enrolled, enter your username and the current 6-digit code.</p>
				<form method="post" action="#encodeForHtmlAttribute( cgi.script_name )#" class="row g-2">
					<input type="hidden" name="action" value="verify">
					<div class="col-auto">
						<input
							type="text"
							name="username"
							class="form-control"
							placeholder="alice@example.com"
							autocomplete="username"
							required>
					</div>
					<div class="col-auto">
						<input
							type="text"
							name="code"
							class="form-control"
							inputmode="numeric"
							autocomplete="one-time-code"
							pattern="\d{6}"
							maxlength="6"
							placeholder="123456"
							required>
					</div>
					<div class="col-auto">
						<button type="submit" class="btn btn-success">Verify code</button>
					</div>
				</form>
			</div>
		</div>

	</cfif>

	<!-- "How this works" card. -->
	<div class="card mb-4">
		<div class="card-header"><strong>How TOTP works</strong></div>
		<div class="card-body">
			<ol class="mb-0">
				<li>At setup, the server generates a random <strong>secret</strong> and Base32-encodes it.</li>
				<li>You scan it (as a QR / <code>otpauth://</code> link) into your authenticator app, so phone and server now share the secret.</li>
				<li>Both sides compute <code>HMAC-SHA1(secret, floor(unix_time / 30))</code> and keep 6 digits - a new code every 30 seconds.</li>
				<li>You type the current code; the server computes what it expects and compares (allowing one step of clock drift).</li>
				<li>Nothing but the 6 digits is ever sent, and only someone holding the secret can produce them.</li>
			</ol>
		</div>
	</div>

	<!-- Caveats card. -->
	<div class="card mb-4">
		<div class="card-header"><strong>What a production version must add</strong></div>
		<div class="card-body">
			<ul class="mb-0">
				<li>Run MFA <strong>after</strong> a first factor (password, passkey, magic link) - never instead of one.</li>
				<li>Store each secret in a <strong>database, encrypted at rest</strong>; it is as sensitive as a password.</li>
				<li>Prevent <strong>replay</strong>: remember the last accepted time-step per user and reject a re-used code.</li>
				<li>Add <strong>rate limiting / lockout</strong> on bad codes, and issue <strong>backup recovery codes</strong> for lost phones.</li>
			</ul>
		</div>
	</div>

	<footer class="text-center text-muted small mt-5">
		<div>CF Summit 2026 - MFA / TOTP demo. Educational use only.</div>
	</footer>

</div>

</body>
</html>
</cfoutput>
