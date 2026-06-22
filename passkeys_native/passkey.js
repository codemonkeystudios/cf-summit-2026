/*
	CF Summit 2026 demo: passkey (WebAuthn) browser-side helper.
	Plain JavaScript, no frameworks, no build step.

	This file:
	- Reads the username from the form.
	- Calls the ColdFusion passkey_example.cfm endpoint to start a WebAuthn ceremony (registration or authentication).
	- Converts Base64URL <-> ArrayBuffer for WebAuthn API I/O.
	- Calls navigator.credentials.create() / .get().
	- Sends the response back to ColdFusion to finish the ceremony.

	Educational reminders:
	* WebAuthn requires a Secure Context: HTTPS, except for localhost.
	* Browser/platform support varies - always feature-detect.
	* Production must do full cryptographic verification on the server.
*/

(function () {
	"use strict";

/*
	Base64URL <-> ArrayBuffer
	WebAuthn passes binary fields as ArrayBuffers in the browser
	but we ferry them across HTTP as Base64URL strings (URL-safe,
	no padding). These two helpers are the bridge.
*/

	function base64url_to_array_buffer(base64url_value) {
		// Restore standard Base64 alphabet and padding before atob.
		var standard_base64 = base64url_value.replace(/-/g, "+").replace(/_/g, "/");
		var padding_length = ( 4 - ( standard_base64.length % 4 ) ) % 4;

		if ( padding_length ) {
			standard_base64 += "=".repeat( padding_length );
		}

		var binary_string = window.atob(standard_base64);
		var output_buffer = new ArrayBuffer(binary_string.length);
		var buffer_view = new Uint8Array(output_buffer);
		for (var byte_index = 0; byte_index < binary_string.length; byte_index++) {
			buffer_view[byte_index] = binary_string.charCodeAt(byte_index);
		}
		return output_buffer;
	}

	function array_buffer_to_base64url(input_buffer) {
		var byte_array = new Uint8Array(input_buffer);
		var binary_string = "";
		for (var byte_index = 0; byte_index < byte_array.byteLength; byte_index++) {
			binary_string += String.fromCharCode(byte_array[byte_index]);
		}
		var standard_base64 = window.btoa(binary_string);
		return standard_base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
	}

	// JSON fetch helper. Sends optional JSON and receives JSON from passkey_example.cfm.
	async function call_json(endpoint_url, request_body) {
		var fetch_options = {
			method: request_body ? "POST" : "GET",
			credentials: "same-origin",
			headers: { "Accept": "application/json" }
		};
		if (request_body) {
			fetch_options.headers["Content-Type"] = "application/json";
			fetch_options.body = JSON.stringify(request_body);
		}

		var http_response = await fetch(endpoint_url, fetch_options);
		var response_text = await http_response.text();
		var response_data;
		try {
			response_data = JSON.parse(response_text);
		} catch (parse_error) {
			throw new Error("Server did not return JSON. Raw response: " + response_text.substring(0, 200));
		}
		if (!http_response.ok) {
			throw new Error("HTTP " + http_response.status + ": " + (response_data && response_data.error ? response_data.error : "request failed"));
		}
		return response_data;
	}

	// Small UI helpers.
	function get_username() {
		var username_input = document.getElementById("passkey_username");
		var username_value = username_input ? username_input.value.trim() : "";
		if (!username_value) { throw new Error("Please enter an email or username first."); }
		return username_value;
	}

	function set_status(alert_variant, message_text) {
		// alert_variant is one of Bootstrap's alert variants: success, danger, warning, info
		var status_box = document.getElementById("passkey_status");
		if (!status_box) { return; }
		status_box.className = "alert alert-" + alert_variant;
		status_box.textContent = message_text;
		status_box.classList.remove("d-none");
	}

	// Build the "Current session" line via DOM nodes so user-supplied usernames cannot inject HTML into the page.
	function refresh_current_user() {
		call_json("passkey_example.cfm?action=current_user")
			.then(function (current_user) {
				var current_user_box = document.getElementById("passkey_current_user");
				if (!current_user_box) { return; }
				current_user_box.textContent = "";
				if (current_user.signed_in) {
					var signed_in_badge = document.createElement("span");
					signed_in_badge.className = "badge bg-success";
					signed_in_badge.textContent = "Signed in";
					current_user_box.appendChild(signed_in_badge);
					current_user_box.appendChild(document.createTextNode(" "));

					var username_node = document.createElement("strong");
					username_node.textContent = current_user.username;
					current_user_box.appendChild(username_node);
					current_user_box.appendChild(document.createTextNode(" "));

					var metadata_node = document.createElement("span");
					metadata_node.className = "text-muted";
					metadata_node.textContent = "(sign_count: " + current_user.sign_count + ", created: " + current_user.created_at + ")";
					current_user_box.appendChild(metadata_node);
				} else {
					var signed_out_badge = document.createElement("span");
					signed_out_badge.className = "badge bg-secondary";
					signed_out_badge.textContent = "Not signed in";
					current_user_box.appendChild(signed_out_badge);
				}
			})
			.catch(function () { /* swallow on initial load */ });
	}

	/*
		Registration flow:
		1. Ask CF for creation options.
		2. Convert Base64URL fields to ArrayBuffers.
		3. Call navigator.credentials.create().
		4. Build a JSON-safe payload from the browser credential.
		5. POST the response (Base64URL'd) back to CF.
	*/
	async function start_passkey_registration() {
		try {
			if (!window.PublicKeyCredential) {
				throw new Error("This browser does not support WebAuthn.");
			}
			var username = get_username();
			set_status("info", "Requesting registration options for " + username + "...");

			// 1. Ask ColdFusion for PublicKeyCredentialCreationOptions.
			var creation_options = await call_json(
				"passkey_example.cfm?action=start_registration",
				{ username: username }
			);

			// 2. Convert Base64URL fields to ArrayBuffers, as required by the WebAuthn API.
			var public_key_options = {
				challenge: base64url_to_array_buffer(creation_options.challenge),
				rp: creation_options.rp,
				user: {
					id: base64url_to_array_buffer(creation_options.user.id),
					name: creation_options.user.name,
					displayName: creation_options.user.displayName
				},
				pubKeyCredParams: creation_options.pubKeyCredParams,
				authenticatorSelection: creation_options.authenticatorSelection,
				timeout: creation_options.timeout,
				attestation: creation_options.attestation
			};

			set_status("info", "Browser is asking the authenticator to create a new passkey...");

			// 3. Trigger the browser/authenticator UI (Touch ID, Windows Hello, security key, ...).
			var new_credential = await navigator.credentials.create({ publicKey: public_key_options });
			if (!new_credential) { throw new Error("Authenticator returned no credential."); }

			// 4. Build a JSON-safe payload for ColdFusion.
			var registration_payload = {
				id: new_credential.id,
				raw_id: array_buffer_to_base64url(new_credential.rawId),
				type: new_credential.type,
				response: {
					client_data_json: array_buffer_to_base64url(new_credential.response.clientDataJSON),
					attestation_object: array_buffer_to_base64url(new_credential.response.attestationObject)
				}
			};

			// 5. Send it back to ColdFusion to finalize.
			var registration_result = await call_json(
				"passkey_example.cfm?action=finish_registration",
				registration_payload
			);

			if (registration_result.ok) {
				set_status("success", "Passkey registered for " + registration_result.username + ".");
			} else {
				set_status("danger", "Registration failed: " + (registration_result.error || "unknown"));
			}
			refresh_current_user();
		} catch (caught_error) {
			console.error(caught_error);
			set_status("danger", caught_error.message || String(caught_error));
		}
	}

	/*
		Authentication flow:
		1. Ask CF for request options (with allowCredentials).
		2. Convert Base64URL fields to ArrayBuffers.
		3. Call navigator.credentials.get().
		4. POST the assertion (Base64URL'd) back to CF.
	*/
	async function start_passkey_authentication() {
		try {
			if (!window.PublicKeyCredential) {
				throw new Error("This browser does not support WebAuthn.");
			}
			var username = get_username();
			set_status("info", "Requesting authentication options for " + username + "...");

			var request_options = await call_json(
				"passkey_example.cfm?action=start_authentication",
				{ username: username }
			);

			var public_key_options = {
				challenge: base64url_to_array_buffer(request_options.challenge),
				allowCredentials: (request_options.allowCredentials || []).map(function (credential_descriptor) {
					return {
						type: credential_descriptor.type,
						id: base64url_to_array_buffer(credential_descriptor.id)
					};
				}),
				userVerification: request_options.userVerification,
				timeout: request_options.timeout
			};

			set_status("info", "Browser is asking the authenticator to sign the challenge...");

			var new_assertion = await navigator.credentials.get({ publicKey: public_key_options });
			if (!new_assertion) { throw new Error("Authenticator returned no assertion."); }

			var authentication_payload = {
				id: new_assertion.id,
				raw_id: array_buffer_to_base64url(new_assertion.rawId),
				type: new_assertion.type,
				response: {
					client_data_json: array_buffer_to_base64url(new_assertion.response.clientDataJSON),
					authenticator_data: array_buffer_to_base64url(new_assertion.response.authenticatorData),
					signature: array_buffer_to_base64url(new_assertion.response.signature),
					user_handle: new_assertion.response.userHandle
						? array_buffer_to_base64url(new_assertion.response.userHandle)
						: null
				}
			};

			var authentication_result = await call_json(
				"passkey_example.cfm?action=finish_authentication",
				authentication_payload
			);

			if (authentication_result.ok) {
				set_status("success", "Signed in as " + authentication_result.username + " (sign_count: " + authentication_result.sign_count + ").");
			} else {
				set_status("danger", "Authentication failed: " + (authentication_result.error || "unknown"));
			}
			refresh_current_user();
		} catch (caught_error) {
			console.error(caught_error);
			set_status("danger", caught_error.message || String(caught_error));
		}
	}

	// Logout: just clears the session-side demo flag.
	async function logout_passkey_demo() {
		try {
			await call_json("passkey_example.cfm?action=logout", {});
			set_status("info", "Logged out.");
			refresh_current_user();
		} catch (caught_error) {
			set_status("danger", caught_error.message || String(caught_error));
		}
	}

	// Wire up DOM events on load.
	document.addEventListener("DOMContentLoaded", function () {
		var register_button = document.getElementById("passkey_register_btn");
		var signin_button = document.getElementById("passkey_signin_btn");
		var logout_button = document.getElementById("passkey_logout_btn");
		if (register_button) { register_button.addEventListener("click", start_passkey_registration); }
		if (signin_button) { signin_button.addEventListener("click", start_passkey_authentication); }
		if (logout_button) { logout_button.addEventListener("click", logout_passkey_demo); }
		refresh_current_user();
	});

	// Expose for console-level inspection during the talk.
	window.passkey_demo = {
		start_passkey_registration: start_passkey_registration,
		start_passkey_authentication: start_passkey_authentication,
		logout_passkey_demo: logout_passkey_demo,
		base64url_to_array_buffer: base64url_to_array_buffer,
		array_buffer_to_base64url: array_buffer_to_base64url
	};
})();
