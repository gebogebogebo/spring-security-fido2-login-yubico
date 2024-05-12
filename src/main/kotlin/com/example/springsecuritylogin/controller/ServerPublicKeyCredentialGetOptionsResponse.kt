package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.Status
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialRequestOptions
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs

class ServerPublicKeyCredentialGetOptionsResponse(
    val challenge: String?,
    val timeout: Long?,
    val rpId: String?,
    val allowCredentials: List<PublicKeyCredentialDescriptor>?,
    val userVerification: UserVerificationRequirement?,
    val extensions: AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput>?,
) : ServerResponse(Status.OK, "") {
    constructor(
        status: Status,
        errorMessage: String,
    ) : this(
        null,
        null,
        null,
        null,
        null,
        null,
    ) {
        this.status = status
        this.errorMessage = errorMessage
    }

    constructor(
        authOptionResponse: PublicKeyCredentialRequestOptions,
    ) : this(
        authOptionResponse.challenge.toString(),
        authOptionResponse.timeout,
        authOptionResponse.rpId,
        authOptionResponse.allowCredentials,
        authOptionResponse.userVerification,
        authOptionResponse.extensions
    )
}
