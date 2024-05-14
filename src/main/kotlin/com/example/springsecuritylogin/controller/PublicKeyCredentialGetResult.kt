package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.Assertion
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs
import com.webauthn4j.data.extension.client.ExtensionClientOutput

class PublicKeyCredentialGetResult {
    val id: String = ""
    val response: AuthenticatorAssertionResponse? = null
    val clientExtensionResults: AuthenticationExtensionsClientOutputs<ExtensionClientOutput>? = null
    val type: String? = null

    class AuthenticatorAssertionResponse {
        val userHandle: String = ""
        val authenticatorData: String = ""
        val clientDataJSON: String = ""
        val signature: String = ""
    }

    fun toAssertion(): Assertion {
        val mapper = jacksonObjectMapper()
        val publicKeyCredentialJson = mapper.writeValueAsString(this)
        return Assertion(publicKeyCredentialJson)
    }

}
