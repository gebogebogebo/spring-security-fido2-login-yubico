package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.Status
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs
import com.yubico.webauthn.data.AssertionExtensionInputs
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.UserVerificationRequirement

class ServerPublicKeyCredentialGetOptionsResponse(
    val challenge: String?,
    val timeout: Long?,
    val rpId: String?,
    val allowCredentials: List<PublicKeyCredentialDescriptor>?,
    val userVerification: UserVerificationRequirement?,
    val extensions: AssertionExtensionInputs?,
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
        authOptionResponse.challenge.base64Url,
        authOptionResponse.timeout.orElse(null),
        authOptionResponse.rpId,
        authOptionResponse.allowCredentials.orElse(null),
        authOptionResponse.userVerification.orElse(null),
        authOptionResponse.extensions
    )
}
