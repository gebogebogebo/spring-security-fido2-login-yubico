package com.example.springsecuritylogin.service

import com.webauthn4j.credential.CredentialRecord
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions

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

}
