<cfscript>
	/*
		base32_selfcheck.cfm
		==========================================================
		A tiny verification page for the MFA demo's Base32 encoder. Open it in a browser to
		confirm mfa.cfc produces correct RFC 4648 output on YOUR ColdFusion engine (CFML
		bitwise behaviour can vary). Not part of the demo flow - just a sanity check.
	*/
	mfa_service = new mfa();
	report = mfa_service.base32_self_check();
</cfscript>
<cfoutput>
<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Base32 self-check &middot; CF Summit 2026 MFA demo</title>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
	<style>body { background: ##f7f7fb; } .wrap { max-width: 680px; }</style>
</head>
<body>
<div class="container wrap py-4">

	<h1 class="h4 mb-3">MFA Base32 self-check</h1>

	<div class="alert alert-#( report.passed ? 'success' : 'danger' )#">
		<strong>#( report.passed ? "All checks passed." : "Some checks FAILED." )#</strong>
		RFC 4648 vectors + a generated-secret round-trip.
	</div>

	<table class="table table-sm bg-white border">
		<thead>
			<tr><th>Input</th><th>Expected</th><th>Got</th><th>Result</th></tr>
		</thead>
		<tbody>
			<cfloop array="#report.results#" index="row">
				<tr>
					<td><code>#encodeForHtml( row.input )#</code></td>
					<td><code>#encodeForHtml( row.expected )#</code></td>
					<td><code>#encodeForHtml( row.got )#</code></td>
					<td>#( row.passed ? '<span class="badge bg-success">pass</span>' : '<span class="badge bg-danger">fail</span>' )#</td>
				</tr>
			</cfloop>
		</tbody>
	</table>

	<a href="mfa_example.cfm" class="btn btn-link p-0">Back to the MFA demo</a>

</div>
</body>
</html>
</cfoutput>
