package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.Attestation
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs

class PublicKeyCredentialCreateResult {
    val id: String = ""
    val response: AuthenticatorAttestationResponse? = null
    val clientExtensionResults: ClientRegistrationExtensionOutputs? = null
    val type: String = ""

    class AuthenticatorAttestationResponse {
        val attestationObject: String = ""
        val clientDataJSON: String = ""
    }

    fun toAttestation(): Attestation {
        val mapper = jacksonObjectMapper()
        val publicKeyCredentialJson = mapper.writeValueAsString(this)
        return Attestation(publicKeyCredentialJson)
    }
}
