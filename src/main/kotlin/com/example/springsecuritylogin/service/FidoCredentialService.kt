package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.repository.MfidoCredentialForYubico

interface FidoCredentialService {
    fun save(userId: String, attestationVerifyResult: AttestationVerifyResult)
    fun load(userInternalId: String, credentialId: ByteArray):  MfidoCredentialForYubico?
}
