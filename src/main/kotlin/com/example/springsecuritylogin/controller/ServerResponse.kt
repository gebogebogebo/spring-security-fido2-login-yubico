package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.Status

open class ServerResponse(
    var status: Status,
    var errorMessage: String,
)
