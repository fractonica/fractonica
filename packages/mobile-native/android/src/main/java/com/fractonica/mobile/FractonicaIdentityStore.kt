package com.fractonica.mobile

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import expo.modules.kotlin.exception.CodedException
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal enum class FractonicaIdentityLifecycle(val wireValue: Byte) {
  INITIALIZING(1),
  ESTABLISHED(2),
}

internal data class FractonicaStoredIdentity(
  val lifecycle: FractonicaIdentityLifecycle,
  val material: ByteArray,
) {
  fun changingLifecycle(value: FractonicaIdentityLifecycle) = copy(lifecycle = value)

  fun hasSameMaterial(other: FractonicaStoredIdentity): Boolean =
    material.contentEquals(other.material)
}

internal class FractonicaIdentityStoreException(
  code: String,
  message: String,
  cause: Throwable? = null,
  val requiresRecovery: Boolean = false,
) : CodedException(code, message, cause)

internal class FractonicaIdentityStore(context: Context) {
  private val identityFile = AtomicFile(File(context.noBackupFilesDir, "fractonica-identity-v1.enc"))
  private val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

  fun load(): FractonicaStoredIdentity? {
    if (!identityFile.baseFile.exists()) return null
    val key = existingWrappingKey() ?: throw identityCorrupt()
    val container = identityFile.readFully()
    var plainText: ByteArray? = null
    return try {
      val decrypted = decrypt(container, key)
      plainText = decrypted
      decode(decrypted)
    } catch (error: FractonicaIdentityStoreException) {
      throw error
    } catch (error: Exception) {
      throw identityUnavailable(error)
    } finally {
      plainText?.fill(0)
    }
  }

  fun createInitializing(material: ByteArray): FractonicaStoredIdentity {
    load()?.let { return it }
    if (material.isEmpty() || material.size > MAX_MATERIAL_BYTES) throw identityCorrupt()
    val identity = FractonicaStoredIdentity(
      lifecycle = FractonicaIdentityLifecycle.INITIALIZING,
      material = material.copyOf(),
    )
    val key = existingWrappingKey() ?: createWrappingKey()
    try {
      persist(identity, key)
    } finally {
      identity.material.fill(0)
    }
    return load() ?: throw identityCorrupt()
  }

  fun markEstablished(expected: FractonicaStoredIdentity) {
    val current = load() ?: throw identityConflict()
    try {
      if (!current.hasSameMaterial(expected)) throw identityConflict()
      if (current.lifecycle == FractonicaIdentityLifecycle.ESTABLISHED) return
      val key = existingWrappingKey() ?: throw identityCorrupt()
      persist(current.changingLifecycle(FractonicaIdentityLifecycle.ESTABLISHED), key)
    } finally {
      current.material.fill(0)
    }
  }

  /** Removes protected state only after Rust has reset the local data store. */
  fun delete() {
    try {
      identityFile.delete()
      if (identityFile.baseFile.exists()) throw identityUnavailable()
      if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
    } catch (error: FractonicaIdentityStoreException) {
      throw error
    } catch (error: Exception) {
      throw identityUnavailable(error)
    }
  }

  private fun existingWrappingKey(): SecretKey? = try {
    keyStore.getKey(KEY_ALIAS, null) as? SecretKey
  } catch (error: Exception) {
    throw identityUnavailable(error)
  }

  private fun createWrappingKey(): SecretKey = try {
    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
    generator.init(
      KeyGenParameterSpec.Builder(
        KEY_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
      )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setRandomizedEncryptionRequired(true)
        .setUserAuthenticationRequired(false)
        .build(),
    )
    generator.generateKey()
  } catch (error: Exception) {
    throw identityUnavailable(error)
  }

  private fun encrypt(plainText: ByteArray, key: SecretKey): ByteArray = try {
    val cipher = Cipher.getInstance(TRANSFORMATION)
    cipher.init(Cipher.ENCRYPT_MODE, key)
    cipher.updateAAD(MAGIC)
    MAGIC + cipher.iv + cipher.doFinal(plainText)
  } catch (error: Exception) {
    throw identityUnavailable(error)
  }

  private fun decrypt(container: ByteArray, key: SecretKey): ByteArray {
    if (container.size < MAGIC.size + IV_BYTES + 1 + TAG_BYTES ||
      container.size > MAGIC.size + IV_BYTES + 1 + MAX_MATERIAL_BYTES + TAG_BYTES ||
      !container.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)
    ) {
      throw identityCorrupt()
    }
    return try {
      val ivStart = MAGIC.size
      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(
        Cipher.DECRYPT_MODE,
        key,
        GCMParameterSpec(TAG_BYTES * 8, container.copyOfRange(ivStart, ivStart + IV_BYTES)),
      )
      cipher.updateAAD(MAGIC)
      cipher.doFinal(container.copyOfRange(ivStart + IV_BYTES, container.size))
    } catch (error: Exception) {
      throw identityCorrupt(error)
    }
  }

  private fun encode(identity: FractonicaStoredIdentity): ByteArray =
    byteArrayOf(identity.lifecycle.wireValue) + identity.material

  private fun persist(identity: FractonicaStoredIdentity, key: SecretKey) {
    val plainText = encode(identity)
    try {
      writeAtomically(encrypt(plainText, key))
    } finally {
      plainText.fill(0)
    }
  }

  private fun decode(value: ByteArray): FractonicaStoredIdentity {
    if (value.size <= 1 || value.size > 1 + MAX_MATERIAL_BYTES) throw identityCorrupt()
    val lifecycle = FractonicaIdentityLifecycle.entries.firstOrNull { it.wireValue == value[0] }
      ?: throw identityCorrupt()
    return FractonicaStoredIdentity(
      lifecycle = lifecycle,
      material = value.copyOfRange(1, value.size),
    )
  }

  private fun writeAtomically(value: ByteArray) {
    var output: FileOutputStream? = null
    try {
      output = identityFile.startWrite()
      output.write(value)
      identityFile.finishWrite(output)
    } catch (error: Exception) {
      output?.let(identityFile::failWrite)
      throw identityUnavailable(error)
    }
  }

  private fun identityUnavailable(cause: Throwable? = null) = FractonicaIdentityStoreException(
    "ERR_FRACTONICA_IDENTITY_UNAVAILABLE",
    "The protected Fractonica identity is temporarily unavailable.",
    cause,
  )

  private fun identityCorrupt(cause: Throwable? = null) = FractonicaIdentityStoreException(
    "ERR_FRACTONICA_IDENTITY_CORRUPT",
    "The protected Fractonica identity is incomplete or corrupt.",
    cause,
    requiresRecovery = true,
  )

  private fun identityConflict() = FractonicaIdentityStoreException(
    "ERR_FRACTONICA_IDENTITY_CONFLICT",
    "The protected Fractonica identity changed during initialization.",
    requiresRecovery = true,
  )

  private companion object {
    const val ANDROID_KEY_STORE = "AndroidKeyStore"
    const val KEY_ALIAS = "fractonica.identity.wrap.v1"
    const val TRANSFORMATION = "AES/GCM/NoPadding"
    const val IV_BYTES = 12
    const val TAG_BYTES = 16
    const val MAX_MATERIAL_BYTES = 1_024
    val MAGIC = "FRACTKS1".encodeToByteArray()
  }
}
