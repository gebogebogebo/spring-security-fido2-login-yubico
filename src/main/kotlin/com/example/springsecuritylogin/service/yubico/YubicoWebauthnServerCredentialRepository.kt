package com.example.springsecuritylogin.service.yubico

import com.example.springsecuritylogin.repository.MfidoCredentialRepository
import com.example.springsecuritylogin.repository.MuserRepository
import com.example.springsecuritylogin.service.FidoCredentialService
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
    private val fidoCredentialService: FidoCredentialService,
) : CredentialRepository {

    override fun getCredentialIdsForUsername(userId: String): Set<PublicKeyCredentialDescriptor> {
        val mUser = mUserRepository.findById(userId).orElse(null) ?: return emptySet()

        return mFidoCredentialRepository.findByUserInternalId(mUser.internalId)
            .map {
                PublicKeyCredentialDescriptor.builder()
                    .id(ByteArray(it.credentialId))
                    .build()
            }
            .toSet()
    }

    override fun getUserHandleForUsername(p0: String?): Optional<ByteArray> {
        TODO("Not yet implemented")
    }

    override fun getUsernameForUserHandle(userHandle: ByteArray): Optional<String> {
        val userInternalId = String(userHandle.bytes)
        val mUser = mUserRepository.findByInternalId(userInternalId) ?: return Optional.empty()

        return Optional.of(mUser.id)
    }

    override fun lookup(credentialId: ByteArray, userHandle: ByteArray): Optional<RegisteredCredential> {
        val userInternalId = String(userHandle.bytes)

        val credential = fidoCredentialService.load(userInternalId, credentialId.bytes) ?: return Optional.empty()

        return Optional.of(
            RegisteredCredential.builder()
                .credentialId(credentialId)
                .userHandle(userHandle)
                .publicKeyCose(ByteArray(credential.credentialPublicKey))
                .signatureCount(credential.signCount)
                .build()
        )
    }

    override fun lookupAll(p0: ByteArray): Set<RegisteredCredential> {
        TODO("Not yet implemented")
    }
}
