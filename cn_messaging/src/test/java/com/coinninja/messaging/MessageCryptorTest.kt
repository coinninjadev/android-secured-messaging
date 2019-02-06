package com.coinninja.messaging

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.junit.MockitoJUnitRunner
import java.nio.charset.Charset
import java.security.SecureRandom
import java.security.Security
import java.security.spec.KeySpec
import java.util.*
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

@RunWith(MockitoJUnitRunner::class)

class MessageCryptorTest {
    val password = "xrS7AJk+V6L8J?B%"
    val rnd = SecureRandom()
    val saltLength = 32
    val keyLength = 128
    val iterationCount = 10000
    val salt: ByteArray = ByteArray(saltLength)
    var messageCryptor = MessageCryptor()
//    Reciever's public key - base16
    val uncompressedPublicKey = "04cbab386ceaa74c2b77ec2c0ddea3fec6c9b0e16bbbb322db458353faacaad53ffaaa7dc3aee53616e0157c19cf8443fd83feb8d54184d3920703c0846105248c"
    //base64
    val encryptionKeyBase64 = "rqcLXf0yHmSHIRaoXO2jnD+gVODrIil0w9DEDesbzdM="
    val hmacBase64 = "GwX848SPaO3qnOpor6BNRMMe+Y8h3RVDzZfQjgUzP/Y="
    val ephemeralPublicKeyBase64 = "BBS6AnMOS9Y+uGsEDYQycHHzcC7PPmzuKDtSda842AtSANZjgm++vr8uEc/bWacKQDL+/KyL3CuIs+m+ueejbBs="
    @Before
    fun setUp() {
    }

    fun generateEncryptionKey() {
        rnd.nextBytes(salt)
        Security.addProvider(BouncyCastleProvider())
        val factoryBC: SecretKeyFactory =
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "BC")
        val keyspecBC: KeySpec = PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength)
        val keyBC: SecretKey = factoryBC.generateSecret(keyspecBC)
        System.out.println(keyBC.javaClass.name)
        System.out.println(Hex.toHexString(keyBC.getEncoded()))
        System.out.println(Hex.toHexString(keyBC.getEncoded()).length)
    }

    @Test
    fun `encryption of message`() {

        val dataToEncrypt = "Hello World".toByteArray()
        val encryptionKey = Base64.getDecoder().decode(encryptionKeyBase64)
        val hmac = Base64.getDecoder().decode(hmacBase64)

        val ephemeralPublicKey = Base64.getDecoder().decode(ephemeralPublicKeyBase64)
        val encrypted = messageCryptor.encrypt(dataToEncrypt, encryptionKey, hmac, ephemeralPublicKey)

        assertThat(ephemeralPublicKey, equalTo(encrypted.slice((encrypted.size-65)..(encrypted.size-1)).toByteArray()))
    }

    @Ignore
    @Test
    fun `decryption of message`() {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

}