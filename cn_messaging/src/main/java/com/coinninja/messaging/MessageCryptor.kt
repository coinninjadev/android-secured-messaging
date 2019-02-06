package com.coinninja.messaging

import org.cryptonode.jncryptor.AES256JNCryptor


class MessageCryptor {

    fun encrypt(dataToEncrypt: ByteArray, encryptionKey: ByteArray, hmac: ByteArray): ByteArray {
        val jnCryptor = AES256JNCryptor()
        return "".toByteArray()
    }


    fun decrypt(dataToDecrypt: ByteArray, decryptionKey: ByteArray): ByteArray {

        return "".toByteArray()
    }
}