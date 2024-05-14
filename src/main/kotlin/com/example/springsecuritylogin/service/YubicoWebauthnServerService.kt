package com.example.springsecuritylogin.service

import com.webauthn4j.credential.CredentialRecord
import com.yubico.webauthn.AssertionRequest

interface YubicoWebauthnServerService {
    fun getRegisterOption(
        userId: String,
    ): RegisterOption

    fun verifyRegisterAttestation(
        registerOption: RegisterOption,
        attestation: Attestation,
    ): AttestationVerifyResult

    fun getAuthenticateOption(): AssertionRequest

    fun verifyAuthenticateAssertion(
        challengeStr: String,
        assertion: Assertion,
        assertionRequest: AssertionRequest,
        publicKeyCredentialJson: String,
        credentialRecord: CredentialRecord
    ): Boolean

}
