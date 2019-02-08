package com.coinninja.message

import androidx.test.runner.AndroidJUnit4
import com.coinninja.bindings.DerivationPath
import com.coinninja.bindings.Libbitcoin
import com.coinninja.messaging.MessageCryptor
import org.hamcrest.CoreMatchers.equalTo

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*

@RunWith(AndroidJUnit4::class)
class EndToEndEncryptionTest {

    @Test
    fun endToEnd() {
        val libbitcoin = Libbitcoin()

        //get a receiver uncompressed public key for derivationPath
        val derivationPath = DerivationPath(49, 0, 0, 0, 0)
        val uncompressedPublicKey = libbitcoin.getUncompressedPublicKey(derivationPath)

        //sender builds encryption keys from rupk
        val encryptionKeys = libbitcoin.getEncryptionKeys(uncompressedPublicKey)

        val messageCryptor = MessageCryptor()

        val dataToEncrypt = "Howdy Doody".toByteArray()
        val encryptedMessage = messageCryptor.encrypt(
            dataToEncrypt,
            encryptionKeys.encryptionKey,
            encryptionKeys.hmacKey,
            encryptionKeys.ephemeralPublicKey
        )

        // receiver extracts ephemeralPublicKey from the encrypted payload
        val ephemeralPublicKey = messageCryptor.unpackEphemeralPublicKey(encryptedMessage)

        //receiver builds decryption keys from ephemeral public key and derivationPath
        val decryptionKeys = libbitcoin.getDecryptionKeys(derivationPath, ephemeralPublicKey)

        val decryptedMessage = messageCryptor.decrypt(encryptedMessage, decryptionKeys.encryptionKey, decryptionKeys.hmacKey)

        assertThat(decryptedMessage, equalTo<ByteArray>(dataToEncrypt))

    }
}
