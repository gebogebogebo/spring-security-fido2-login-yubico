package com.example.springsecuritylogin.service

import com.webauthn4j.credential.CredentialRecord

interface FidoCredentialService {
    fun save(userId: String, credentialId: ByteArray, credentialRecord: CredentialRecord)
    fun load(userInternalId: String, credentialId: String): Pair<CredentialRecord?,String?>
}
