/*
 * Copyright 2026 Davils
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.davils.krypt.primitive.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.KeyFailure
import kotlinx.io.bytestring.ByteString

private const val IV_BYTES: Int = 16
private const val SALT_BYTES: Int = 16
private const val MINIMUM_SALT: Int = 8
private const val MAXIMUM_SALT: Int = 1_024
private const val AES_256_BYTES: Int = 32
private const val AES_128_BYTES: Int = 16
private const val MAXIMUM_KEY_BYTES: Int = 64

internal object Pbes2 {
    private val PRFS: Map<ObjectIdentifier, DigestAlgorithm> = mapOf(
        Oids.HMAC_SHA256 to DigestAlgorithm.Sha256,
        Oids.HMAC_SHA512 to DigestAlgorithm.Sha512,
    )
    private val KDFS: Map<DigestAlgorithm, KdfAlgorithm> = mapOf(
        DigestAlgorithm.Sha256 to KdfAlgorithm.Pbkdf2Sha256,
        DigestAlgorithm.Sha512 to KdfAlgorithm.Pbkdf2Sha512,
    )

    private val CIPHERS: Map<ObjectIdentifier, Int> = mapOf(
        Oids.AES_256_CBC to AES_256_BYTES,
        Oids.AES_128_CBC to AES_128_BYTES,
    )

    suspend fun encrypt(crypto: Crypto, plaintext: SecretBytes, password: SecretText, iterations: Int): ByteString {
        val salt = ByteString(crypto.environment.random.bytes(SALT_BYTES))
        val iv = ByteString(crypto.environment.random.bytes(IV_BYTES))
        val key = crypto.derivations.pbkdf2(
            password = password,
            salt = salt,
            iterations = iterations,
            length = AES_256_BYTES,
        )
        val encrypted = key.use { secret ->
            plaintext.reveal { bytes ->
                crypto.backend.aesCbcEncrypt(key = secret, iv = iv.toByteArray(), data = bytes)
            }
        }
        return Der.encode {
            sequence {
                sequence {
                    objectIdentifier(Oids.PBES2)
                    sequence {
                        writePbkdf2(salt = salt, iterations = iterations)
                        sequence {
                            objectIdentifier(Oids.AES_256_CBC)
                            octetString(iv)
                        }
                    }
                }
                octetString(ByteString(encrypted))
            }
        }
    }

    suspend fun decrypt(crypto: Crypto, encoded: ByteString, password: SecretText): Outcome<SecretBytes, KeyFailure> {
        val parameters = Der.decodeOrNull(encoded) { readEncryptedPrivateKeyInfo() }
            ?: return Outcome.Failure(KeyFailure.UnsupportedEncryption)
        val policy = crypto.environment.policy
        return when (policy.permitsIterations(parameters.kdf.iterations, AlgorithmUse.Verify)) {
            true -> decryptWith(crypto, parameters, password)
            false -> Outcome.Failure(KeyFailure.Refused)
        }
    }

    private suspend fun decryptWith(
        crypto: Crypto,
        parameters: Pbes2Parameters,
        password: SecretText,
    ): Outcome<SecretBytes, KeyFailure> {
        val algorithm = KDFS.getValue(parameters.kdf.digest)
        crypto.permit(algorithm, AlgorithmUse.Verify)
        val derived = crypto.backend.pbkdf2(
            digest = parameters.kdf.digest,
            password = password,
            salt = parameters.kdf.salt.toByteArray(),
            iterations = parameters.kdf.iterations,
            length = parameters.keyBytes,
        )
        val key = SecretBytes.adopt(derived)
        val plaintext = key.use { secret ->
            crypto.backend.aesCbcDecrypt(
                key = secret,
                iv = parameters.iv.toByteArray(),
                data = parameters.encrypted.toByteArray(),
            )
        }
        val decrypted = plaintext?.let { bytes -> Outcome.Success(SecretBytes.adopt(bytes)) }
        return decrypted ?: Outcome.Failure(KeyFailure.WrongPassword)
    }

    private fun DerWriter.writePbkdf2(salt: ByteString, iterations: Int) {
        sequence {
            objectIdentifier(Oids.PBKDF2)
            sequence {
                octetString(salt)
                integer(iterations.toLong())
                integer(AES_256_BYTES.toLong())
                sequence {
                    objectIdentifier(Oids.HMAC_SHA256)
                    nullValue()
                }
            }
        }
    }

    private fun DerReader.readEncryptedPrivateKeyInfo(): Pbes2Parameters = readSequence {
        val (kdf, cipher) = readSequence {
            expect(readObjectIdentifier() == Oids.PBES2, "PBES2")
            readSequence { readSequence { readPbkdf2() } to readSequence { readCipher() } }
        }
        val encrypted = readOctetString()
        val keyBytes = kdf.keyBytes ?: cipher.first
        expect(keyBytes == cipher.first, "a key length that fits the cipher")
        Pbes2Parameters(kdf = kdf, keyBytes = keyBytes, iv = cipher.second, encrypted = encrypted)
    }

    private fun DerReader.readPbkdf2(): Pbkdf2Parameters {
        expect(readObjectIdentifier() == Oids.PBKDF2, "PBKDF2")
        return readSequence {
            val salt = readOctetString()
            expect(salt.size in MINIMUM_SALT..MAXIMUM_SALT, "a salt of 8 to 1024 bytes")
            val iterations = readInt(1..Int.MAX_VALUE)
            val keyBytes = Tag.Integer.takeIf { tag -> isNext(tag) }?.let { readInt(1..MAXIMUM_KEY_BYTES) }
            val digest = readSequence { readPrf() }
            Pbkdf2Parameters(salt = salt, iterations = iterations, keyBytes = keyBytes, digest = digest)
        }
    }

    private fun DerReader.readPrf(): DigestAlgorithm {
        val digest = PRFS[readObjectIdentifier()]
        readRemaining()
        return digest ?: refuse(DerFailure.InvalidValue, "an HMAC with SHA-2")
    }

    private fun DerReader.readCipher(): Pair<Int, ByteString> {
        val keyBytes = CIPHERS[readObjectIdentifier()] ?: refuse(DerFailure.InvalidValue, "AES-CBC")
        val iv = readOctetString()
        expect(iv.size == IV_BYTES, "an IV of 16 bytes")
        return keyBytes to iv
    }

    private fun DerReader.expect(isValid: Boolean, detail: String) {
        if (!isValid) refuse(DerFailure.InvalidValue, detail)
    }
}
