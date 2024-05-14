package com.example.springsecuritylogin.service

interface WebauthnServerService {
    fun getRegisterOption(
        userId: String,
    ): RegisterOption

    fun verifyRegisterAttestation(
        registerOption: RegisterOption,
        attestation: Attestation,
    ): AttestationVerifyResult

    fun getAuthenticateOption(): AuthenticateOption

    fun verifyAuthenticateAssertion(
        authenticateOption: AuthenticateOption,
        assertion: Assertion,
    ): Boolean

    fun toUserInternalId(encodedUserHandle: String): String

}
