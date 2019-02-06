package com.coinninja.messaging

import org.cryptonode.jncryptor.AES256JNCryptor
import org.cryptonode.jncryptor.JNCryptor
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.SecretKeySpec


class MessageCryptor {

    fun encrypt(
        dataToEncrypt: ByteArray, encryptionKey: ByteArray, hmac: ByteArray,
        ephemeralPublicKey: ByteArray
    ): ByteArray {
        val encryptionKeySecret = SecretKeySpec(encryptionKey, "AES")
        val hmacSecret = SecretKeySpec(hmac, "AES")
        val encryptData = AES256JNCryptor().encryptData(dataToEncrypt, encryptionKeySecret, hmacSecret)

        return encryptData + ephemeralPublicKey
    }
    // base64 string version?


    fun decrypt(dataToDecrypt: ByteArray, encryptionKey: ByteArray, hmac: ByteArray): ByteArray {
        val encryptionKeySecret = SecretKeySpec(encryptionKey, "AES")
        val hmacSecret = SecretKeySpec(hmac, "AES")

        return AES256JNCryptor().decryptData(
            dataToDecrypt.slice(0..(dataToDecrypt.size - 66)).toByteArray(),
            encryptionKeySecret,
            hmacSecret
        )
    }

    fun unpackEphemeralPublicKey(dataToDecrypt: ByteArray): ByteArray {
        return dataToDecrypt.slice((dataToDecrypt.size - 65)..(dataToDecrypt.size - 1)).toByteArray()
    }
}