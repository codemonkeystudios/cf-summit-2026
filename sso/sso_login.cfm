<cfscript>
	/*
		sso_login.cfm
		==========================================================
		The OAuth page. The <cfoauth> tag runs the WHOLE Single Sign-On round trip for
		you, and this one page is BOTH the "start sign-in" and the "callback" endpoint:

			- First request:  <cfoauth> redirects the browser to the provider's sign-in page.
			- Return request: the provider sends the user back HERE; <cfoauth> swaps the
			                  one-time code for an access token and fills the result struct.

		SET UP (Google)
			1. Create an OAuth 2.0 Client ID at https://console.cloud.google.com
			   (Application type: "Web application").
			2. Add THIS page's full URL as an "Authorized redirect URI", for example
			       https://your-app.example.com/sso/sso_login.cfm
			   <cfoauth> defaults its redirecturi to the URL that is executing, so the URL
			   you register must match the URL this page is served from, exactly.
			3. Put the Client ID and secret below. In production, load these from
			   environment variables or a secrets store - never hard-code real secrets.

		OTHER PROVIDERS
			type="facebook" works the same way. For Microsoft, GitHub, Okta, etc. you omit
			"type" and instead supply authendpoint + accesstokenendpoint (see the commented
			example at the bottom of this file). The result handling stays the same.
	*/

	// Shared demo settings - also defines the safe session-rotation helper we use below.
	include "../demo_config.cfm";

	// --- Provider configuration. Replace these with your real values. ---
	google_client_id  = "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com";
	google_secret_key = "YOUR_GOOGLE_CLIENT_SECRET";
</cfscript>

<!--- Friendly guard so the demo does not bounce to Google with placeholder credentials.
      Check BOTH the client id and the secret - either one left as a placeholder is wrong. --->
<cfif findNoCase( "YOUR_GOOGLE", google_client_id ) || findNoCase( "YOUR_GOOGLE", google_secret_key )>
	<cfoutput>
		<!doctype html>
		<html lang="en">
		<head>
			<meta charset="utf-8">
			<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
		</head>
		<body class="bg-light">
			<div class="container py-5" style="max-width: 680px;">
				<div class="alert alert-warning">
					<h1 class="h5">Add your Google OAuth credentials</h1>
					<p class="mb-0">
						Edit <code>sso_login.cfm</code> and set <code>google_client_id</code> and
						<code>google_secret_key</code>, then register this page's URL as an
						<em>Authorized redirect URI</em> in the Google Cloud console.
					</p>
				</div>
				<a href="sso_example.cfm" class="btn btn-link">Back</a>
			</div>
		</body>
		</html>
	</cfoutput>
	<cfabort>
</cfif>

<cfscript>
	/*
		CSRF protection with a "state" value. The idea: send a random value to the provider
		when we START sign-in, and require the SAME value to come back when the provider
		RETURNS. An attacker cannot forge a callback because they cannot guess our state.

		We branch on whether this is the start leg or the return leg. The provider returns
		with url.code present, so:
		  - no url.code  -> START: mint a fresh state and remember it in the session.
		  - url.code      -> RETURN: the value we remembered must match what came back.
	*/
	if ( structKeyExists( url, "code" ) ) {
		returned_state = url.state ?: "";
		expected_state = session.oauth_state ?: "";

		if ( !len( expected_state ) || returned_state != expected_state ) {
			// Missing or mismatched state -> possible CSRF / stale tab. Refuse and restart.
			structDelete( session, "oauth_state" );
			location( url = "sso_example.cfm?sso_error=1", addtoken = false );
		}
	} else {
		session.oauth_state = lCase( replace( createUUID(), "-", "", "all" ) );
	}
</cfscript>

<!---
	The SSO round trip. <cfoauth> is a tag (there is no cfscript equivalent you need).
	type="google" makes ColdFusion use Google's known authorisation + token endpoints.
	scope is what we ask the user to share; "email,profile" is all we need to identify them.

	state: we pass our random value so the provider echoes it back on the return leg.
	NOTE: depending on the ColdFusion build, <cfoauth> may also validate state internally
	and/or may not surface the returned value other than as url.state. We validate url.state
	ourselves above when it is present; if your runtime does not expose it, that explicit
	check is a no-op and you are relying on the tag's own protection - confirm which applies.
--->
<cfoauth
	type="google"
	clientid="#google_client_id#"
	secretkey="#google_secret_key#"
	scope="email,profile"
	state="#session.oauth_state#"
	result="oauth_result">

<cfscript>
	/*
		Execution only reaches here AFTER a successful sign-in. (Before that, <cfoauth>
		has already redirected the browser away to the provider.) The result struct holds:
			oauth_result.access_token  - token for calling provider APIs (not needed for plain SSO)
			oauth_result.name          - the user's display name
			oauth_result.other         - provider profile sub-struct (Google: email, picture, ...)
	*/
	if ( structKeyExists( variables, "oauth_result" ) && len( oauth_result.access_token ?: "" ) ) {
		profile = oauth_result.other ?: {};

		/*
			THIS is the single-sign-on step: map the provider's verified identity onto a
			signed-in user in your app. A real app would look up (or create) a local user
			account keyed on this email instead of just trusting the raw profile.
		*/
		// New privilege level -> rotate the session id BEFORE storing the user
		// (session-fixation defence). See ../demo_config.cfm.
		rotate_session_if_available();

		session.sso_user = {
			"name": oauth_result.name ?: ( profile.name ?: "" ),
			"email": profile.email ?: "",
			"picture": profile.picture ?: ""
		};

		// One-time use: clear the state now that this sign-in is complete.
		structDelete( session, "oauth_state" );

		location( url = "sso_example.cfm", addtoken = false );
	}

	// If we reach this point, sign-in did not complete (for example, the user cancelled
	// on the provider's screen). Send them back to the start with an error flag.
	location( url = "sso_example.cfm?sso_error=1", addtoken = false );
</cfscript>

<!---
	=====================================================================================
	CUSTOM PROVIDER (Microsoft, GitHub, Okta, Auth0, ...) - for reference, not run here.
	Omit "type" and point <cfoauth> at the provider's own OAuth 2 endpoints:

	<cfoauth
		clientid="#my_client_id#"
		secretkey="#my_secret_key#"
		authendpoint="https://github.com/login/oauth/authorize"
		accesstokenendpoint="https://github.com/login/oauth/access_token"
		scope="read:user,user:email"
		result="oauth_result">

	Everything after the tag (reading oauth_result, storing the session) is the same.
	=====================================================================================
--->
