package com.example.springsecuritylogin.service.yubico

import com.example.springsecuritylogin.repository.MfidoCredentialForYubico
import com.example.springsecuritylogin.repository.MfidoCredentialRepository
import com.example.springsecuritylogin.repository.MuserRepository
import com.example.springsecuritylogin.service.AttestationVerifyResult
import com.example.springsecuritylogin.service.FidoCredentialService
import org.springframework.stereotype.Service


@Service
class FidoCredentialServiceImpl(
    private val mUserRepository: MuserRepository,
    private val mFidoCredentialRepository: MfidoCredentialRepository,
) : FidoCredentialService {
    override fun save(userId: String, attestationVerifyResult: AttestationVerifyResult) {
        val mUser = mUserRepository.findByUserId(userId) ?: throw RuntimeException("User not found")

        val entity = MfidoCredentialForYubico(
            0,
            mUser.internalId,
            attestationVerifyResult.credentialId,
            attestationVerifyResult.signCount,
            attestationVerifyResult.credentialPublicKey
        )
        mFidoCredentialRepository.save(entity)
    }

    override fun load(userInternalId: String, credentialId: ByteArray):  MfidoCredentialForYubico? {
        val credential = mFidoCredentialRepository.findByUserInternalId(userInternalId)
            .find { it.credentialId.contentEquals(credentialId) }
        return credential
    }
}
