package com.coinninja.messaging

import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.junit.MockitoJUnitRunner
import java.util.*

@RunWith(MockitoJUnitRunner::class)

class MessageCryptorTest {
    var messageCryptor = MessageCryptor()
    val encrypted = "AwDVbESpwTj3VllUN9l4igjkPk3pIUahlOF32v2sGhjX7m3vqos/LAnju3cPO8AR/GUTE9xpmqg/ED0IpsanFib2BBS6AnMOS9Y+uGsEDYQycHHzcC7PPmzuKDtSda842AtSANZjgm++vr8uEc/bWacKQDL+/KyL3CuIs+m+ueejbBs="
    val encryptionKeyBase64 = "rqcLXf0yHmSHIRaoXO2jnD+gVODrIil0w9DEDesbzdM="
    val hmacBase64 = "GwX848SPaO3qnOpor6BNRMMe+Y8h3RVDzZfQjgUzP/Y="
    val ephemeralPublicKeyBase64 = "BBS6AnMOS9Y+uGsEDYQycHHzcC7PPmzuKDtSda842AtSANZjgm++vr8uEc/bWacKQDL+/KyL3CuIs+m+ueejbBs="

    @Test
    fun `encryption and decryption of message`() {

        val dataToEncrypt = "Hello World".toByteArray()
        val encryptionKey = Base64.getDecoder().decode(encryptionKeyBase64)
        val encryptHmac = Base64.getDecoder().decode(hmacBase64)

        val ephemeralPublicKey = Base64.getDecoder().decode(ephemeralPublicKeyBase64)
        val encrypted = messageCryptor.encrypt(dataToEncrypt, encryptionKey, encryptHmac, ephemeralPublicKey)

        val decoded = Base64.getEncoder().encode(encrypted)

        assertThat(ephemeralPublicKey, equalTo(encrypted.slice((encrypted.size-65)..(encrypted.size-1)).toByteArray()))

        val decrypted = messageCryptor.decrypt(encrypted, encryptionKey, encryptHmac)
        assertThat(dataToEncrypt, equalTo(decrypted))
    }

    @Test
    fun `encryption and decryption of message base64Strings`() {

        val dataToEncrypt = "Hello World".toByteArray()
        val encryptionKey = Base64.getDecoder().decode(encryptionKeyBase64)
        val encryptHmac = Base64.getDecoder().decode(hmacBase64)

        val ephemeralPublicKey = Base64.getDecoder().decode(ephemeralPublicKeyBase64)
        val decoded = messageCryptor.encryptAsBase64(dataToEncrypt, encryptionKey, encryptHmac, ephemeralPublicKey)

        val decrypted = messageCryptor.decrypt(decoded, encryptionKey, encryptHmac)
        assertThat(dataToEncrypt, equalTo(decrypted))
    }

    @Test
    fun `Ephemeral key from encrypted`(){
        val unpackEphemeralPublicKey = messageCryptor.unpackEphemeralPublicKey(Base64.getDecoder().decode(encrypted))
        assertThat(unpackEphemeralPublicKey, equalTo(Base64.getDecoder().decode(ephemeralPublicKeyBase64)))
    }

    @Test
    fun `Ephemeral key from encrypted string`(){
        val unpackEphemeralPublicKey = messageCryptor.unpackEphemeralPublicKey(encrypted)
        assertThat(unpackEphemeralPublicKey, equalTo(Base64.getDecoder().decode(ephemeralPublicKeyBase64)))
    }

}