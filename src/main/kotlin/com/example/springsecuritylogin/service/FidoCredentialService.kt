package com.example.springsecuritylogin.service

interface FidoCredentialService {
    fun save(userId: String, attestationVerifyResult: AttestationVerifyResult)
//    fun load(userInternalId: String, credentialId: String): Pair<CredentialRecord?,String?>
}
