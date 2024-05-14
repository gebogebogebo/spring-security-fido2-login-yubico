package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.RegisterOption
import com.example.springsecuritylogin.service.Status
import com.yubico.webauthn.data.AttestationConveyancePreference
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
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
        registerOption: RegisterOption,
    ) : this(
        registerOption.publicKeyCredentialCreationOptions.rp,
        registerOption.publicKeyCredentialCreationOptions.user,
        registerOption.publicKeyCredentialCreationOptions.attestation,
        registerOption.publicKeyCredentialCreationOptions.authenticatorSelection.orElse(null),
        registerOption.publicKeyCredentialCreationOptions.challenge.base64Url,
        registerOption.publicKeyCredentialCreationOptions.excludeCredentials.orElse(null),
        registerOption.publicKeyCredentialCreationOptions.pubKeyCredParams,
        registerOption.publicKeyCredentialCreationOptions.timeout.orElse(null),
        registerOption.publicKeyCredentialCreationOptions.extensions,
    )
}
