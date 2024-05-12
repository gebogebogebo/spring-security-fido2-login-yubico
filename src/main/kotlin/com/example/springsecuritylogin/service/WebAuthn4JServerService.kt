package com.example.springsecuritylogin.service

import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.data.PublicKeyCredentialCreationOptions
import com.webauthn4j.data.PublicKeyCredentialRequestOptions

interface WebAuthn4JServerService {
    fun getRegisterOption(
        userId: String,
    ): PublicKeyCredentialCreationOptions

    fun verifyRegisterAttestation(
        challengeStr: String,
        attestation: Attestation,
    ): Pair<ByteArray, CredentialRecord>

    fun getAuthenticateOption(): PublicKeyCredentialRequestOptions

    fun verifyAuthenticateAssertion(
        challengeStr: String,
        assertion: Assertion,
        credentialRecord: CredentialRecord
    ): Boolean

    fun toUserInternalId(encodedUserHandle: String): String
}
