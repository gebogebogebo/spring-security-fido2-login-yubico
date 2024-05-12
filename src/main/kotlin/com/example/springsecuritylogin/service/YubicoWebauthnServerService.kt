package com.example.springsecuritylogin.service

import com.webauthn4j.credential.CredentialRecord
import com.yubico.webauthn.AssertionRequest
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions

interface YubicoWebauthnServerService {
    fun getRegisterOption(
        userId: String,
    ): PublicKeyCredentialCreationOptions

    fun verifyRegisterAttestation(
        challengeStr: String,
        publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions,
        attestation: Attestation,
        publicKeyCredentialJson: String,
//    ): Pair<ByteArray, CredentialRecord>
    )

    fun getAuthenticateOption(): AssertionRequest

    fun verifyAuthenticateAssertion(
        challengeStr: String,
        assertion: Assertion,
        assertionRequest: AssertionRequest,
        publicKeyCredentialJson: String,
        credentialRecord: CredentialRecord
    ): Boolean

}
