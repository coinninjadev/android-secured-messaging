package com.coinninja.messaging

import android.util.Base64
import org.cryptonode.jncryptor.AES256JNCryptor
import javax.crypto.spec.SecretKeySpec


open class MessageCryptor {

    open fun encrypt(
        dataToEncrypt: ByteArray, encryptionKey: ByteArray, hmac: ByteArray,
        ephemeralPublicKey: ByteArray
    ): ByteArray {
        val encryptionKeySecret = SecretKeySpec(encryptionKey, "AES")
        val hmacSecret = SecretKeySpec(hmac, "AES")
        val encryptData = AES256JNCryptor().encryptData(dataToEncrypt, encryptionKeySecret, hmacSecret)

        return encryptData + ephemeralPublicKey
    }

    open fun encryptAsBase64(
        dataToEncrypt: ByteArray, encryptionKey: ByteArray, hmac: ByteArray,
        ephemeralPublicKey: ByteArray
    ): String? {
        return Base64.encodeToString(encrypt(dataToEncrypt, encryptionKey, hmac, ephemeralPublicKey), Base64.DEFAULT)
    }

    open fun decrypt(dataToDecrypt: ByteArray, encryptionKey: ByteArray, hmac: ByteArray): ByteArray {
        val encryptionKeySecret = SecretKeySpec(encryptionKey, "AES")
        val hmacSecret = SecretKeySpec(hmac, "AES")

        return AES256JNCryptor().decryptData(
            dataToDecrypt.slice(0..(dataToDecrypt.size - 66)).toByteArray(),
            encryptionKeySecret,
            hmacSecret
        )
    }

    open fun decrypt(dataToDecryptBase64: String?, encryptionKey: ByteArray, hmac: ByteArray): ByteArray {
        return decrypt(Base64.decode(dataToDecryptBase64, Base64.DEFAULT), encryptionKey, hmac)
    }

    open fun unpackEphemeralPublicKey(dataToDecrypt: ByteArray): ByteArray {
        return dataToDecrypt.slice((dataToDecrypt.size - 65)..(dataToDecrypt.size - 1)).toByteArray()
    }

    open fun unpackEphemeralPublicKey(dataToDecryptBase64: String): ByteArray {
        return unpackEphemeralPublicKey(Base64.decode(dataToDecryptBase64, Base64.DEFAULT))
    }
}