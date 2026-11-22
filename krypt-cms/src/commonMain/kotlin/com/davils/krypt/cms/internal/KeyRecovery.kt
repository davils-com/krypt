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

@file:OptIn(LegacyCryptography::class)

package com.davils.krypt.cms.internal

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.enveloped.Credential
import com.davils.krypt.cms.enveloped.RecipientType
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

private const val ML_KEM_768_BITS: Int = 768
private const val ML_KEM_1024_BITS: Int = 1_024

private val KEM_BITS: Map<KemAlgorithm, Int> = mapOf(
    KemAlgorithm.MlKem768 to ML_KEM_768_BITS,
    KemAlgorithm.MlKem1024 to ML_KEM_1024_BITS,
)

private val ORIGINATORS: Map<KeyFamily, ObjectIdentifier> = mapOf(
    KeyFamily.Ec to CmsOids.EC_PUBLIC_KEY,
    KeyFamily.X25519 to CmsOids.X25519,
    KeyFamily.X448 to CmsOids.X448,
)

internal class KeyRecovery(private val crypto: Crypto) {
    fun candidate(parsed: ParsedRecipient, credential: Credential): Candidate? = when (credential) {
        is Credential.Certified -> certified(parsed, credential)
        is Credential.Kek -> kek(parsed, credential)
        is Credential.Password -> password(parsed, credential)
    }

    suspend fun recover(candidate: Candidate.Usable): SecretBytes? = when (candidate) {
        is Candidate.Transport -> transport(candidate)

        is Candidate.Agreement -> agreement(candidate)

        is Candidate.Kem -> kem(candidate)

        is Candidate.Kek -> unwrap(
            kek = candidate.credential.key,
            wrapped = candidate.recipient.encryptedKey,
            wrap = candidate.recipient.wrap,
        )

        is Candidate.Password -> password(candidate)
    }

    private fun certified(parsed: ParsedRecipient, credential: Credential.Certified): Candidate? {
        val certificate = credential.certificate
        return when (parsed) {
            is ParsedRecipient.Transport -> {
                Candidate.Transport(parsed, credential).takeIf {
                    parsed.reference.matches(certificate)
                }
            }

            is ParsedRecipient.Agreement -> {
                parsed.keys
                    .firstOrNull { (reference, _) -> reference.matches(certificate) }
                    ?.let { (_, encryptedKey) -> Candidate.Agreement(parsed, credential, encryptedKey) }
            }

            is ParsedRecipient.Kem -> {
                Candidate.Kem(parsed, credential).takeIf { parsed.reference.matches(certificate) }
            }

            is ParsedRecipient.Unsupported -> {
                Candidate.Unsupported.takeIf {
                    parsed.references.any { reference -> reference.matches(certificate) }
                }
            }

            is ParsedRecipient.Kek -> {
                null
            }

            is ParsedRecipient.Password -> {
                null
            }
        }
    }

    private fun kek(parsed: ParsedRecipient, credential: Credential.Kek): Candidate? = when (parsed) {
        is ParsedRecipient.Kek -> Candidate.Kek(parsed, credential).takeIf {
            parsed.keyIdentifier == credential.keyIdentifier
        }

        is ParsedRecipient.Unsupported -> Candidate.Unsupported.takeIf {
            parsed.keyIdentifier == credential.keyIdentifier
        }

        is ParsedRecipient.Transport -> null

        is ParsedRecipient.Agreement -> null

        is ParsedRecipient.Password -> null

        is ParsedRecipient.Kem -> null
    }

    private fun password(parsed: ParsedRecipient, credential: Credential.Password): Candidate? = when (parsed) {
        is ParsedRecipient.Password -> Candidate.Password(parsed, credential)
        is ParsedRecipient.Unsupported -> Candidate.Unsupported.takeIf { parsed.type == RecipientType.Password }
        is ParsedRecipient.Transport -> null
        is ParsedRecipient.Agreement -> null
        is ParsedRecipient.Kek -> null
        is ParsedRecipient.Kem -> null
    }

    private suspend fun transport(candidate: Candidate.Transport): SecretBytes? {
        val recipient = candidate.recipient
        val key = candidate.credential.privateKey.takeIf { found -> found.family == KeyFamily.Rsa }
        return key?.let { found ->
            crypto.encryptions.decrypt(
                privateKey = found,
                ciphertext = recipient.encryptedKey,
                algorithm = recipient.algorithm,
            )
        }
    }

    private suspend fun agreement(candidate: Candidate.Agreement): SecretBytes? {
        val recipient = candidate.recipient
        val privateKey = candidate.credential.privateKey
        val ephemeral = ephemeralKey(recipient, privateKey) ?: return null
        val secret = crypto.agreements.agree(privateKey, ephemeral)
        val kek = secret.use { shared ->
            KeyDerivation.agreementKek(
                crypto = crypto,
                secret = shared,
                scheme = recipient.scheme,
                wrap = recipient.wrap,
                userKeyingMaterial = recipient.userKeyingMaterial,
            )
        }
        return unwrapWith(kek = kek, wrapped = candidate.encryptedKey, wrap = recipient.wrap)
    }

    private fun ephemeralKey(recipient: ParsedRecipient.Agreement, privateKey: PrivateKey): PublicKey? {
        val expected = ORIGINATORS[privateKey.family] ?: return null
        val isScheme = recipient.scheme.isHkdf == (privateKey.family != KeyFamily.Ec)
        val isUsable = isScheme && recipient.originatorAlgorithm == expected
        val parameters = privateKey.curve?.let { curve -> ObjectIdentifier.of(curve.objectIdentifier) }
        val encoded = Der.encode {
            sequence {
                sequence {
                    objectIdentifier(expected)
                    parameters?.let { curve -> objectIdentifier(curve) }
                }
                bitString(BitString(recipient.originatorKey))
            }
        }
        val decoded = encoded.takeIf { isUsable }?.let { found -> crypto.keys.decodePublic(found) }
        return decoded?.getOrNull()
    }

    private suspend fun kem(candidate: Candidate.Kem): SecretBytes? {
        val recipient = candidate.recipient
        val privateKey = candidate.credential.privateKey
        val isKem = privateKey.family == KeyFamily.MlKem && privateKey.bits == KEM_BITS.getValue(recipient.kem)
        val shared = privateKey.takeIf { isKem }?.let { key ->
            crypto.kems.decapsulate(recipient = key, encapsulated = recipient.ciphertext, algorithm = recipient.kem)
        } ?: return null
        val wrap = recipient.wrap
        val info = KeyDerivation.kemInfo(
            wrap = wrap,
            kekLength = wrap.keyBytes,
            userKeyingMaterial = recipient.userKeyingMaterial,
        )
        val kek = shared.use { secret ->
            crypto.derivations.hkdf(
                inputKey = secret,
                salt = ByteString(),
                info = info,
                length = wrap.keyBytes,
                algorithm = recipient.kdf,
            )
        }
        return unwrapWith(kek = kek, wrapped = recipient.encryptedKey, wrap = wrap)
    }

    private suspend fun password(candidate: Candidate.Password): SecretBytes? {
        val recipient = candidate.recipient
        val cipher = recipient.cipher
        val kek = KeyDerivation.passwordKek(
            crypto = crypto,
            password = candidate.credential.password,
            derivation = recipient.derivation,
            length = cipher.encryption.keyBytes,
        )
        return kek.use { derived ->
            PasswordWrap.unwrap(crypto = crypto, kek = derived, iv = cipher.iv, wrapped = recipient.encryptedKey)
        }
    }

    private suspend fun unwrapWith(kek: SecretBytes, wrapped: ByteString, wrap: KeyWrapAlgorithm): SecretBytes? {
        val key = kek.use { bytes -> SecretKey.of(bytes) }
        val unwrapped = crypto.keyWraps.unwrap(kek = key, wrapped = wrapped, algorithm = wrap)
        key.destroy()
        return unwrapped
    }

    private suspend fun unwrap(kek: SecretKey, wrapped: ByteString, wrap: KeyWrapAlgorithm): SecretBytes? =
        kek.takeIf { key -> key.bits == wrap.keyBytes * Byte.SIZE_BITS }?.let { key ->
            crypto.keyWraps.unwrap(kek = key, wrapped = wrapped, algorithm = wrap)
        }
}
