component {

	/*
		Application.cfc
		Minimal session support so the CF Summit 2026 auth demos work when this folder is
		served on its own. ColdFusion walks UP the directory tree to find Application.cfc,
		so this ONE file at the package root covers every demo subfolder (magic_link,
		passkeys_cf, passkeys_native, sso, mfa).

		Intentionally tiny: just session management + sensible demo timeouts. No
		onApplicationStart/onRequest lifecycle code - the demos initialise their own
		application-scoped stores on first use.
	*/

	this.name = "cfsummit2026_auth_demos";
	this.applicationTimeout = createTimeSpan( 0, 2, 0, 0 ); // 2 hours
	this.sessionManagement = true;
	this.sessionTimeout = createTimeSpan( 0, 1, 0, 0 ); // 1 hour - generous for a workshop

}
