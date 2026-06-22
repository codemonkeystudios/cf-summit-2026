<cfscript>
	/*
		sso_example.cfm
		==========================================================
		The app's home page. It shows a "Sign in with Google" button when nobody is
		signed in, and the signed-in user's profile (pulled from the provider via
		<cfoauth> over in sso_login.cfm) when they are.

		The actual OAuth work lives in sso_login.cfm - this page just reads/clears the
		session that sso_login.cfm populates.
	*/

	// Log out: forget the signed-in user and reload this page.
	if ( structKeyExists( url, "logout" ) ) {
		structDelete( session, "sso_user" );
		location( url = "sso_example.cfm", addtoken = false );
	}

	signed_in = structKeyExists( session, "sso_user" );
	current_user = signed_in ? session.sso_user : { "name": "", "email": "", "picture": "" };
	had_error = structKeyExists( url, "sso_error" );
</cfscript>
<cfoutput>
<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Single Sign-On Demo &middot; CF Summit 2026</title>

	<!-- Bootstrap 5 from CDN. Production should add SRI hashes (integrity=...). -->
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
	<style>
		body { background: ##f7f7fb; }
		.demo-wrap { max-width: 760px; }
		.avatar { width: 56px; height: 56px; border-radius: 50%; object-fit: cover; }
	</style>
</head>
<body>

<div class="container demo-wrap py-4">

	<header class="mb-4">
		<h1 class="h3 mb-1">Single Sign-On Demo</h1>
		<p class="text-muted mb-0">
			CF Summit 2026 - sign in with an external identity provider using the
			built-in <code>&lt;cfoauth&gt;</code> tag.
		</p>
	</header>

	<div class="alert alert-warning" role="alert">
		<strong>Demo only.</strong> Sign-in identifies the user via Google and stores
		their profile in the session. A real app would map this identity onto its own
		user account, serve everything over HTTPS, and keep the client secret out of source.
	</div>

	<cfif had_error>
		<div class="alert alert-danger" role="alert">
			Sign-in was cancelled or did not complete. Please try again.
		</div>
	</cfif>

	<div class="card shadow-sm mb-4">
		<div class="card-body">

			<cfif signed_in>

				<!-- Signed-in panel, built from the provider's profile. -->
				<div class="d-flex align-items-center gap-3 mb-3">
					<cfif len( current_user.picture )>
						<img src="#encodeForHtmlAttribute( current_user.picture )#" alt="" class="avatar">
					</cfif>
					<div>
						<div><span class="badge bg-success">Signed in</span></div>
						<div class="fw-bold">#encodeForHtml( current_user.name )#</div>
						<div class="text-muted">#encodeForHtml( current_user.email )#</div>
					</div>
				</div>
				<a href="#encodeForHtmlAttribute( cgi.script_name )#?logout=1" class="btn btn-outline-secondary">Log out</a>

			<cfelse>

				<!-- Signed-out: the button just links to the <cfoauth> page. -->
				<p class="mb-3">Use your Google account to sign in - no separate password needed.</p>
				<a href="sso_login.cfm" class="btn btn-primary">Sign in with Google</a>

			</cfif>

		</div>
	</div>

	<!-- "How this works" card. -->
	<div class="card mb-4">
		<div class="card-header"><strong>How the SSO flow works</strong></div>
		<div class="card-body">
			<ol class="mb-0">
				<li>The user clicks <strong>Sign in with Google</strong>, which opens <code>sso_login.cfm</code>.</li>
				<li>The <code>&lt;cfoauth&gt;</code> tag redirects the browser to Google's sign-in / consent screen.</li>
				<li>Google authenticates the user and redirects back to <code>sso_login.cfm</code> with a one-time code.</li>
				<li><code>&lt;cfoauth&gt;</code> exchanges that code for an access token and fills the <code>result</code> struct.</li>
				<li>We read the profile from <code>result.other</code> (email, name, picture) and store the signed-in user in the session.</li>
			</ol>
		</div>
	</div>

	<!-- Caveats card. -->
	<div class="card mb-4">
		<div class="card-header"><strong>What a production version must add</strong></div>
		<div class="card-body">
			<ul class="mb-0">
				<li>Keep the client secret <strong>out of source control</strong> - load it from an environment variable or secrets store.</li>
				<li>Register exact <strong>redirect URIs</strong> and serve everything over <strong>HTTPS</strong>.</li>
				<li>Protect against CSRF with the <code>state</code> attribute: send a random value and verify it on return.</li>
				<li><strong>Map the provider identity to your own user record</strong> (look up or provision an account); don't grant access just because the sign-in succeeded.</li>
			</ul>
		</div>
	</div>

	<footer class="text-center text-muted small mt-5">
		<div>CF Summit 2026 - Single Sign-On demo. Educational use only.</div>
	</footer>

</div>

</body>
</html>
</cfoutput>
