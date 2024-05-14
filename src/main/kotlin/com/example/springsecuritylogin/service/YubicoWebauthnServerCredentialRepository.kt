package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.repository.MfidoCredentialRepository
import com.example.springsecuritylogin.repository.MuserRepository
import com.yubico.webauthn.CredentialRepository
import com.yubico.webauthn.RegisteredCredential
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import org.springframework.stereotype.Repository
import java.util.Optional

@Repository
class YubicoWebauthnServerCredentialRepository(
    private val mUserRepository: MuserRepository,
    private val mFidoCredentialRepository: MfidoCredentialRepository,
) : CredentialRepository {

    override fun getCredentialIdsForUsername(userId: String): Set<PublicKeyCredentialDescriptor> {
        // TODO
        return emptySet()
    }

    override fun getUserHandleForUsername(p0: String?): Optional<ByteArray> {
        TODO("Not yet implemented")
    }

    override fun getUsernameForUserHandle(userHandle: ByteArray): Optional<String> {
        // TODO
        return Optional.of("user1")
    }

    override fun lookup(credentialId: ByteArray, userHandle: ByteArray): Optional<RegisteredCredential> {

        /*
        RegisteredCredential.builder()
            .credentialId(credentialId)
            .userHandle(userHandle)
            .publicKeyCose(new ByteArray(authenticatorData.getCredentialPublicKey()))
            .signatureCount(authenticatorData.getSignCount())
            .build()
        */

        TODO("Not yet implemented")
    }

/*
    @Override
    public Optional<RegisteredCredential> lookup(final ByteArray credentialId, final ByteArray userHandle) {

        final String userHandleDec = new String(userHandle.getBytes(), StandardCharsets.UTF_8);

        final Optional<WebAuthnAuthenticatorDataWithType> authenticator = Optional.ofNullable(
                webAuthnAuthenticatorDataWithTypeCache.findByNulabIdAndCredentialId(
                        userHandleDec,
                        credentialId.getBytes(),
                        () -> webAuthnAuthenticatorDataDao.findAllByNulabId(userHandleDec)
                )
        );

        return authenticator
                .filter(auth -> auth.getWebauthnAuthenticatorDataType().isSecurityDevice())
                .map(authenticatorData -> RegisteredCredential.builder()
                        .credentialId(credentialId)
                        .userHandle(userHandle)
                        .publicKeyCose(new ByteArray(authenticatorData.getCredentialPublicKey()))
                        .signatureCount(authenticatorData.getSignCount())
                        .build());
    }

 */
    override fun lookupAll(p0: ByteArray): Set<RegisteredCredential> {
        // TODO
        return emptySet()
    }
}
