package com.example.springsecuritylogin.controller

import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs
import com.webauthn4j.data.extension.client.ExtensionClientOutput

class PublicKeyCredentialGetResult {
    val id: String = ""
    val rawId: String = ""
    val response: AuthenticatorAssertionResponse? = null
    val extensions: AuthenticationExtensionsClientOutputs<ExtensionClientOutput>? = null
    val type: String? = null

    class AuthenticatorAssertionResponse {
        val userHandle: String = ""
        val authenticatorData: String = ""
        val clientDataJSON: String = ""
        val signature: String = ""
    }
}
