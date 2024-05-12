package com.example.springsecuritylogin.service

import java.util.Base64

class Assertion(
    encodedCredentialId: String,
    encodedUserHandle: String,
    encodedAuthenticatorData: String,
    encodedClientDataJSON: String,
    encodedSignature: String,
) {
    private val decoder = Base64.getUrlDecoder()

    val credentialId: ByteArray = decoder.decode(encodedCredentialId)
    val userHandle: ByteArray = decoder.decode(encodedUserHandle)
    val authenticatorData: ByteArray = decoder.decode(encodedAuthenticatorData)
    val clientDataJSON: ByteArray = decoder.decode(encodedClientDataJSON)
    val signature: ByteArray = decoder.decode(encodedSignature)
}
