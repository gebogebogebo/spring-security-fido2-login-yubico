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

    override fun lookup(credentialId: ByteArray, p1: ByteArray?): Optional<RegisteredCredential> {
        TODO("Not yet implemented")
    }

    override fun lookupAll(p0: ByteArray): Set<RegisteredCredential> {
        // TODO
        return emptySet()
    }
}
