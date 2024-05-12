package com.example.springsecuritylogin.controller

import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs
import com.webauthn4j.data.extension.client.ExtensionClientOutput

class PublicKeyCredentialCreateResult {
    val id: String = ""
    val response: AuthenticatorAttestationResponse? = null
    val clientExtensionResults: AuthenticationExtensionsClientOutputs<ExtensionClientOutput>? = null
    val type: String = ""

    class AuthenticatorAttestationResponse {
        val attestationObject: String = ""
        val clientDataJSON: String = ""
    }
}
