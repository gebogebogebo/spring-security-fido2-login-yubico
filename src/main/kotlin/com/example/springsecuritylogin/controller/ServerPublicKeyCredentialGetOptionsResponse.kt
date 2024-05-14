package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.AuthenticateOption
import com.example.springsecuritylogin.service.Status
import com.yubico.webauthn.data.AssertionExtensionInputs
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
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
        authenticateOption: AuthenticateOption,
    ) : this(
        authenticateOption.assertionRequest.publicKeyCredentialRequestOptions.challenge.base64Url,
        authenticateOption.assertionRequest.publicKeyCredentialRequestOptions.timeout.orElse(null),
        authenticateOption.assertionRequest.publicKeyCredentialRequestOptions.rpId,
        authenticateOption.assertionRequest.publicKeyCredentialRequestOptions.allowCredentials.orElse(null),
        authenticateOption.assertionRequest.publicKeyCredentialRequestOptions.userVerification.orElse(null),
        authenticateOption.assertionRequest.publicKeyCredentialRequestOptions.extensions
    )
}
