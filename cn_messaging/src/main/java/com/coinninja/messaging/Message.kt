package com.coinninja.messaging

data class Message constructor(val encryptionKey: ByteArray, val hmac: ByteArray, val message: String)