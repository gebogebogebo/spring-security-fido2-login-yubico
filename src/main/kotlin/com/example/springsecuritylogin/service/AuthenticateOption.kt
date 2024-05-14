package com.example.springsecuritylogin.service

import com.yubico.webauthn.AssertionRequest

class AuthenticateOption(
    val assertionRequest: AssertionRequest
)
