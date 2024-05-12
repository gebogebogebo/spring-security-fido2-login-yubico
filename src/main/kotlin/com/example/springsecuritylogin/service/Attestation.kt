package com.example.springsecuritylogin.service

import java.util.Base64

class Attestation(encodedAttestationObject: String, encodedClientDataJSON: String) {

    private val decoder = Base64.getUrlDecoder()

    val attestationObject: ByteArray = decoder.decode(encodedAttestationObject)
    val clientDataJSON: ByteArray = decoder.decode(encodedClientDataJSON)
}
