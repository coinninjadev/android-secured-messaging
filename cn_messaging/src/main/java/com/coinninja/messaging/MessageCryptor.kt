package com.coinninja.messaging

import org.apache.commons.codec.binary.Base64
import org.cryptonode.jncryptor.AES256JNCryptor
import javax.crypto.spec.SecretKeySpec


open class MessageCryptor {

    fun encrypt(
        dataToEncrypt: ByteArray, encryptionKey: ByteArray, hmac: ByteArray,
        ephemeralPublicKey: ByteArray
    ): ByteArray {
        val encryptionKeySecret = SecretKeySpec(encryptionKey, "AES")
        val hmacSecret = SecretKeySpec(hmac, "AES")
        val encryptData = AES256JNCryptor().encryptData(dataToEncrypt, encryptionKeySecret, hmacSecret)

        return encryptData + ephemeralPublicKey
    }

    fun encryptAsBase64(
        dataToEncrypt: ByteArray, encryptionKey: ByteArray, hmac: ByteArray,
        ephemeralPublicKey: ByteArray
    ): String? {
        return Base64.encodeBase64String(encrypt(dataToEncrypt, encryptionKey, hmac, ephemeralPublicKey))
    }

    fun decrypt(dataToDecrypt: ByteArray, encryptionKey: ByteArray, hmac: ByteArray): ByteArray {
        val encryptionKeySecret = SecretKeySpec(encryptionKey, "AES")
        val hmacSecret = SecretKeySpec(hmac, "AES")

        return AES256JNCryptor().decryptData(
            dataToDecrypt.slice(0..(dataToDecrypt.size - 66)).toByteArray(),
            encryptionKeySecret,
            hmacSecret
        )
    }

    fun decrypt(dataToDecryptBase64: String?, encryptionKey: ByteArray, hmac: ByteArray): ByteArray {
        return decrypt(Base64.decodeBase64(dataToDecryptBase64), encryptionKey, hmac)
    }

    fun unpackEphemeralPublicKey(dataToDecrypt: ByteArray): ByteArray {
        return dataToDecrypt.slice((dataToDecrypt.size - 65)..(dataToDecrypt.size - 1)).toByteArray()
    }

    fun unpackEphemeralPublicKey(dataToDecryptBase64: String): ByteArray {
        return unpackEphemeralPublicKey(Base64.decodeBase64(dataToDecryptBase64))
    }
}