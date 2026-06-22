<cfscript>
	// Shared demo settings (public base URL + session-rotation helper). EDIT ../demo_config.cfm.
	include "../demo_config.cfm";

	// One shared service instance for the whole application, created under a lock so two
	// first-hit requests cannot both build it (double-checked locking).
	if ( !structKeyExists( application, "magic_link" ) ) {
		lock scope="application" type="exclusive" timeout="5" {
			if ( !structKeyExists( application, "magic_link" ) ) {
				application.magic_link = new magic_link();
			}
		}
	}

	/*
		The link we email must use the PUBLIC, browser-visible origin (the user clicks it
		from their inbox, often on another device), so we build it from the configured base
		URL, not from CGI. See ../demo_config.cfm.
	*/
	this_page_url = demo_resolved_base_url & cgi.script_name;

	// View state that the HTML below reads. Modes: request | link_sent | signed_in | error
	signed_in_email = structKeyExists( session, "magic_link_user" ) ? session.magic_link_user : "";
	page_mode = len( signed_in_email ) ? "signed_in" : "request";
	status_variant = "info";
	status_message = "";
	generated_link = "";

	// --- Log out: clear the demo session. ---
	if ( structKeyExists( url, "logout" ) ) {
		structDelete( session, "magic_link_user" );
		signed_in_email = "";
		page_mode = "request";
	}
	// --- The user clicked a magic link: ?token=... ---
	else if ( structKeyExists( url, "token" ) && len( trim( url.token ) ) ) {
		consume_result = application.magic_link.consume_magic_link( url.token );

		if ( consume_result.success ) {
			// New privilege level -> rotate the session id BEFORE storing the user, so we
			// do not depend on how a runtime preserves session contents across rotation.
			rotate_session_if_available();
			session.magic_link_user = consume_result.email_address;

			// Stash a one-shot flash message, then redirect to a CLEAN url so the secret
			// token does not linger in the address bar / history / referer header.
			session.magic_link_flash = "Signed in successfully.";
			location( url = cgi.script_name, addtoken = false );
		} else {
			page_mode = "error";
			status_variant = "danger";
			status_message = consume_result.message;
		}
	}
	// --- The user submitted their email to request a link. ---
	else if ( structKeyExists( form, "email_address" ) ) {
		request_result = application.magic_link.request_magic_link(
			email_address = form.email_address,
			base_url = this_page_url
		);

		if ( request_result.success ) {
			page_mode = "link_sent";
			status_variant = "success";
			status_message = "A sign-in link was created for " & request_result.email_address & ".";
			generated_link = request_result.magic_link_url;
		} else {
			page_mode = "error";
			status_variant = "danger";
			status_message = request_result.message;
		}
	}

	// Show a one-shot flash message after the post-login redirect, then clear it.
	if ( structKeyExists( session, "magic_link_flash" ) ) {
		status_variant = "success";
		status_message = session.magic_link_flash;
		structDelete( session, "magic_link_flash" );
	}
</cfscript>
<cfoutput>
<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Magic Link Demo &middot; CF Summit 2026</title>

	<!-- Bootstrap 5 from CDN. Production should add SRI hashes (integrity=...). -->
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
	<style>
		body { background: ##f7f7fb; }
		.demo-wrap { max-width: 760px; }
		code, pre { word-break: break-all; }
	</style>
</head>
<body>

<div class="container demo-wrap py-4">

	<header class="mb-4">
		<h1 class="h3 mb-1">Magic Link Demo</h1>
		<p class="text-muted mb-0">
			A teaching example for CF Summit 2026 - passwordless email sign-in in ColdFusion.
		</p>
	</header>

	<!-- Demo-only callout. -->
	<div class="alert alert-warning" role="alert">
		<strong>Demo only.</strong> Tokens are kept in server memory and the link is shown
		on screen instead of emailed, so this runs with no database or mail server. See the
		comments in <code>magic_link.cfc</code> for what a production version must add.
	</div>

	<!-- Status line. -->
	<cfif len( status_message )>
		<div class="alert alert-#encodeForHtmlAttribute( status_variant )#" role="status">
			#encodeForHtml( status_message )#
		</div>
	</cfif>

	<div class="card shadow-sm mb-4">
		<div class="card-body">

			<cfif page_mode eq "signed_in">

				<!-- Signed-in panel. -->
				<p class="mb-2">
					<span class="badge bg-success">Signed in</span>
					<strong>#encodeForHtml( signed_in_email )#</strong>
				</p>
				<p class="text-muted">
					Clicking the magic link proved this person controls that inbox, so we
					started a logged-in session for them.
				</p>
				<a href="#encodeForHtmlAttribute( cgi.script_name )#?logout=1" class="btn btn-outline-secondary">Log out</a>

			<cfelseif page_mode eq "link_sent">

				<!-- The generated link. In a real app this would be emailed, not shown. -->
				<p class="mb-2">
					Normally this link would be <strong>emailed</strong> to the user and they
					would click it from their inbox. For the demo, here it is - click to sign in:
				</p>
				<div class="alert alert-light border">
					<a href="#encodeForHtmlAttribute( generated_link )#">#encodeForHtml( generated_link )#</a>
				</div>
				<a href="#encodeForHtmlAttribute( generated_link )#" class="btn btn-primary">Open the link (sign in)</a>
				<a href="#encodeForHtmlAttribute( cgi.script_name )#" class="btn btn-link">Start over</a>

			<cfelse>

				<!-- Request form (also the fallback for the "error" mode). -->
				<form method="post" action="#encodeForHtmlAttribute( cgi.script_name )#">
					<div class="mb-3">
						<label for="email_address" class="form-label">Email address</label>
						<input
							type="email"
							id="email_address"
							name="email_address"
							class="form-control"
							placeholder="alice@example.com"
							autocomplete="email"
							required>
						<div class="form-text">
							We will create a one-time sign-in link for this address.
						</div>
					</div>
					<button type="submit" class="btn btn-primary">Email me a sign-in link</button>
				</form>

			</cfif>

		</div>
	</div>

	<!-- "How this works" card. -->
	<div class="card mb-4">
		<div class="card-header"><strong>How the demo flow works</strong></div>
		<div class="card-body">
			<ol class="mb-0">
				<li>You enter an email address.</li>
				<li>The server generates a long, random, single-use token.</li>
				<li>It stores only a <strong>SHA-256 hash</strong> of the token, with a 15-minute expiry and a "used yet?" flag.</li>
				<li>It builds a link containing the <em>raw</em> token (in a real app this is emailed to you).</li>
				<li>Clicking the link sends the token back; the server hashes it, finds the record, checks it is unused and unexpired, marks it used, and signs you in.</li>
			</ol>
		</div>
	</div>

	<!-- Caveats card. -->
	<div class="card mb-4">
		<div class="card-header"><strong>What a production version must add</strong></div>
		<div class="card-body">
			<ul class="mb-0">
				<li>Store tokens in a <strong>database table</strong>, not server memory, so links survive restarts and work across multiple servers.</li>
				<li>Look up a real user account, and always return the same "check your email" response whether or not the account exists (avoid <strong>email enumeration</strong>).</li>
				<li><strong>Rate limit</strong> requests per email address and per IP so the form cannot be used to spam inboxes.</li>
				<li>Send the link over <strong>HTTPS</strong> and email it to the user instead of showing it on screen.</li>
			</ul>
		</div>
	</div>

	<footer class="text-center text-muted small mt-5">
		<div>CF Summit 2026 - Magic Link demo. Educational use only.</div>
	</footer>

</div>

</body>
</html>
</cfoutput>
