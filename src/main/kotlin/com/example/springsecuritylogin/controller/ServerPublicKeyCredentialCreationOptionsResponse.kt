package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.Status
import com.yubico.webauthn.data.AttestationConveyancePreference
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.RegistrationExtensionInputs
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity

class ServerPublicKeyCredentialCreationOptionsResponse(
    val rp: RelyingPartyIdentity?,
    val user: UserIdentity?,
    val attestation: AttestationConveyancePreference?,
    val authenticatorSelection: AuthenticatorSelectionCriteria?,
    val challenge: String?,
    val excludeCredentials: Set<PublicKeyCredentialDescriptor>?,
    val pubKeyCredParams: List<PublicKeyCredentialParameters>?,
    val timeout: Long?,
    val extensions: RegistrationExtensionInputs?,
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
        null,
        null,
        null,
    ) {
        this.status = status
        this.errorMessage = errorMessage
    }

    constructor(
        regOptionResponse: PublicKeyCredentialCreationOptions,
    ) : this(
        regOptionResponse.rp,
        regOptionResponse.user,
        regOptionResponse.attestation,
        regOptionResponse.authenticatorSelection.orElse(null),
        regOptionResponse.challenge.base64Url,
        regOptionResponse.excludeCredentials.orElse(null),
        regOptionResponse.pubKeyCredParams,
        regOptionResponse.timeout.orElse(null),
        regOptionResponse.extensions,
    )
}
