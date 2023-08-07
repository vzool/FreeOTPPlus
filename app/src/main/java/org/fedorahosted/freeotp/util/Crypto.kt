package org.fedorahosted.freeotp.util

import java.security.Key
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

class Crypto {

    private val cipher: Cipher = Cipher.getInstance("ChaCha20Poly1305")

    fun encrypt(data: ByteArray, key: String): ByteArray {
        val keyHash = MessageDigest.getInstance("SHA-256").digest(key.toByteArray(StandardCharsets.UTF_8))
        val keyBytes = keyHash.copyOf(32)
        val keySpec = SecretKeySpec(keyBytes, "ChaCha20Poly1305")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec)
        return cipher.doFinal(data)
    }

    fun decrypt(data: ByteArray, key: String): ByteArray {
        val keyHash = MessageDigest.getInstance("SHA-256").digest(key.toByteArray(StandardCharsets.UTF_8))
        val keyBytes = keyHash.copyOf(32)
        val keySpec = SecretKeySpec(keyBytes, "ChaCha20Poly1305")
        cipher.init(Cipher.DECRYPT_MODE, keySpec)
        return cipher.doFinal(data)
    }
}

