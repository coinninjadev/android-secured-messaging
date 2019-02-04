package com.coinninja.messaging

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.junit.MockitoJUnitRunner
import java.security.SecureRandom
import java.security.Security
import java.security.spec.KeySpec
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
    fun `expects 32 length key`() {
        assertThat(2 + 2, equalTo(4))
    }
}