package com.example.springsecuritylogin.service

class AttestationVerifyResult(
    val credentialId: ByteArray,
    val signCount: Long,
    val credentialPublicKey: ByteArray,
)
