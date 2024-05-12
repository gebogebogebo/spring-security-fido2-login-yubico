package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.repository.MfidoCredentialRepository
import com.example.springsecuritylogin.repository.MuserRepository
import com.yubico.webauthn.FinishRegistrationOptions
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.StartRegistrationOptions
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.ResidentKeyRequirement
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.UserVerificationRequirement
import org.springframework.stereotype.Service
import java.nio.charset.StandardCharsets

@Service
class YubicoWebauthnServerServiceImpl(
    private val mUserRepository: MuserRepository,
    private val mFidoCredentialRepository: MfidoCredentialRepository,
    private val yubicoWebauthnServerCredentialRepository: YubicoWebauthnServerCredentialRepository,
) : YubicoWebauthnServerService {
    private val rpId = RelyingPartyIdentity.builder()
        .id("localhost")
        .name("yubico-webauthn-server-test")
        .build()

    private val rp = RelyingParty.builder()
        .identity(rpId)
        .credentialRepository(yubicoWebauthnServerCredentialRepository)
        .origins(setOf("http://localhost:8080"))
//                .attestationConveyancePreference(AttestationConveyancePreference.NONE)
//                .allowUntrustedAttestation(true)
//                .validateSignatureCounter(false)
        .build()

    override fun getRegisterOption(userId: String): PublicKeyCredentialCreationOptions {
        val mUser = mUserRepository.findById(userId).orElseThrow { RuntimeException("User not found") }

        val user = UserIdentity.builder()
            .name(mUser.id)
            .displayName(mUser.id)
            .id(createUserId(mUser.internalId))
            .build()

        val authenticatorSelectionCriteria = AuthenticatorSelectionCriteria.builder()
            .residentKey(ResidentKeyRequirement.REQUIRED)
            .userVerification(UserVerificationRequirement.REQUIRED)
//            .authenticatorAttachment(AuthenticatorAttachment.PLATFORM)
            .build()

        val startRegistrationOptions = StartRegistrationOptions.builder()
            .user(user)
            .authenticatorSelection(authenticatorSelectionCriteria)
            .timeout(60000)
            .build()

        return rp.startRegistration(startRegistrationOptions)
    }

    override fun verifyRegisterAttestation(
        challengeStr: String,
        publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions,
        attestation: Attestation,
        publicKeyCredentialJson: String,
//    ): Pair<kotlin.ByteArray, CredentialRecord> {
    ) {

        val pkc = PublicKeyCredential.parseRegistrationResponseJson(publicKeyCredentialJson)

        val finishRegistrationOptions = FinishRegistrationOptions.builder()
            .request(publicKeyCredentialCreationOptions)
            .response(pkc)
            .build()

        val result = rp.finishRegistration(finishRegistrationOptions)

        /*
            result = relyingPartyComponent
                    .getRelyingPartyAttestationNoneForRegistration()
                    .finishRegistration(FinishRegistrationOptions.builder()
                            .request(options)
                            .response(pkc)
                            .build());

         */

        return
    }

    private fun createUserId(userId: String): ByteArray {
        return ByteArray(userId.toByteArray(StandardCharsets.UTF_8))
    }

}
