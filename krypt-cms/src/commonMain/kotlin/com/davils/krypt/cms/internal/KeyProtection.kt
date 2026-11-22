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

package com.davils.krypt.cms.internal

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.cms.enveloped.ContentEncryption
import com.davils.krypt.cms.enveloped.Recipient
import com.davils.krypt.cms.internal.Algorithms.writeContentAlgorithm
import com.davils.krypt.cms.internal.Algorithms.writeHkdf
import com.davils.krypt.cms.internal.Algorithms.writeKem
import com.davils.krypt.cms.internal.Algorithms.writeKeyTransport
import com.davils.krypt.cms.internal.Algorithms.writeKeyWrap
import com.davils.krypt.cms.internal.References.writeRecipientKeyReference
import com.davils.krypt.cms.internal.References.writeReference
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

private const val KEY_IDENTIFIER_VERSION: Long = 2
private const val AGREEMENT_VERSION: Long = 3
private const val KEK_VERSION: Long = 4
private const val SALT_BYTES: Int = 16
private const val IV_BYTES: Int = 16
private const val ORIGINATOR: Int = 0
private const val ORIGINATOR_KEY: Int = 1
private const val UKM: Int = 1
private const val KEM_UKM: Int = 0

internal class KeyProtection(private val crypto: Crypto) {
    suspend fun protect(recipient: Recipient, key: SecretBytes): ByteString = when (recipient) {
        is Recipient.KeyTransport -> transport(recipient, key)
        is Recipient.KeyAgreement -> agreement(recipient, key)
        is Recipient.Kek -> kek(recipient, key)
        is Recipient.Password -> password(recipient, key)
        is Recipient.Kem -> kem(recipient, key)
    }

    private suspend fun transport(recipient: Recipient.KeyTransport, key: SecretBytes): ByteString {
        val publicKey = keyOf(recipient.certificate)
        val encrypted = key.reveal { bytes ->
            crypto.encryptions.encrypt(
                publicKey = publicKey,
                plaintext = ByteString(bytes),
                algorithm = recipient.algorithm,
            )
        }
        val reference = References.of(recipient.certificate, recipient.isKeyIdentifierUsed)
        return Der.encode {
            sequence {
                integer(KEY_IDENTIFIER_VERSION.takeIf { recipient.isKeyIdentifierUsed } ?: 0)
                writeReference(reference)
                writeKeyTransport(recipient.digest)
                octetString(encrypted)
            }
        }
    }

    private suspend fun agreement(recipient: Recipient.KeyAgreement, key: SecretBytes): ByteString {
        val publicKey = keyOf(recipient.certificate)
        val type = requireNotNull(agreementType(publicKey)) { "A ${publicKey.family} key does not agree on a key" }
        val isHkdf = publicKey.family != KeyFamily.Ec
        val scheme = ParsedRecipient.AgreementScheme(digest = recipient.digest, isHkdf = isHkdf)
        val schemeOid = requireNotNull(RecipientCodec.SCHEME_OIDS[scheme]) {
            "Key agreement derives with SHA-256, SHA-384 or SHA-512, not ${recipient.digest.algorithmName}"
        }
        val ephemeral = crypto.keys.generate(type)
        val secret = crypto.agreements.agree(ephemeral.privateKey, publicKey)
        ephemeral.privateKey.destroy()
        val kek = secret.use { shared ->
            KeyDerivation.agreementKek(
                crypto = crypto,
                secret = shared,
                scheme = scheme,
                wrap = recipient.wrap,
                userKeyingMaterial = recipient.userKeyingMaterial,
            )
        }
        val wrapped = crypto.keyWraps.wrap(kek = SecretKey.of(kek), key = key, algorithm = recipient.wrap)
        val reference = References.of(recipient.certificate, recipient.isKeyIdentifierUsed)
        val spki = Der.decode(ephemeral.publicKey.encoded) {
            readSequence {
                readElement()
                readBitString()
            }
        }
        val originator = successOf(spki)
        return Der.encode {
            constructed(RecipientCodec.AGREEMENT) {
                integer(AGREEMENT_VERSION)
                explicit(ORIGINATOR) {
                    constructed(Tag.context(number = ORIGINATOR_KEY, isConstructed = true)) {
                        sequence { objectIdentifier(originatorAlgorithm(publicKey)) }
                        bitString(originator)
                    }
                }
                recipient.userKeyingMaterial?.let { ukm -> explicit(UKM) { octetString(ukm) } }
                sequence {
                    objectIdentifier(schemeOid)
                    writeKeyWrap(recipient.wrap)
                }
                sequence {
                    sequence {
                        writeRecipientKeyReference(reference)
                        octetString(wrapped)
                    }
                }
            }
        }
    }

    private suspend fun kek(recipient: Recipient.Kek, key: SecretBytes): ByteString {
        val wrap = recipient.wrap
        val wrapped = crypto.keyWraps.wrap(kek = recipient.key, key = key, algorithm = wrap)
        return Der.encode {
            constructed(RecipientCodec.KEK) {
                integer(KEK_VERSION)
                sequence { octetString(recipient.keyIdentifier) }
                writeKeyWrap(wrap)
                octetString(wrapped)
            }
        }
    }

    private suspend fun password(recipient: Recipient.Password, key: SecretBytes): ByteString {
        val random = crypto.environment.random
        val salt = ByteString(random.bytes(SALT_BYTES))
        val iv = ByteString(random.bytes(IV_BYTES))
        val encryption = ContentEncryption.Aes256Cbc
        val kek = crypto.derivations.pbkdf2(
            password = recipient.password,
            salt = salt,
            iterations = recipient.iterations,
            length = encryption.keyBytes,
            algorithm = recipient.prf,
        )
        val wrapped = kek.use { derived -> PasswordWrap.wrap(crypto = crypto, kek = derived, iv = iv, key = key) }
        return Der.encode {
            constructed(RecipientCodec.PASSWORD) {
                integer(0)
                constructed(RecipientCodec.DERIVATION) {
                    objectIdentifier(CmsOids.PBKDF2)
                    sequence {
                        octetString(salt)
                        integer(recipient.iterations.toLong())
                        sequence {
                            objectIdentifier(RecipientCodec.PRF_OIDS.getValue(recipient.prf.digest))
                            nullValue()
                        }
                    }
                }
                sequence {
                    objectIdentifier(CmsOids.PWRI_KEK)
                    writeContentAlgorithm(ContentAlgorithm(encryption, iv))
                }
                octetString(wrapped)
            }
        }
    }

    private suspend fun kem(recipient: Recipient.Kem, key: SecretBytes): ByteString {
        val publicKey = keyOf(recipient.certificate)
        require(publicKey.family == KeyFamily.MlKem) { "A KEM recipient has an ML-KEM key" }
        val algorithm = crypto.kems.defaultFor(publicKey)
        val encapsulation = crypto.kems.encapsulate(publicKey, algorithm)
        val wrap = recipient.wrap
        val info = KeyDerivation.kemInfo(
            wrap = wrap,
            kekLength = wrap.keyBytes,
            userKeyingMaterial = recipient.userKeyingMaterial,
        )
        val kek = encapsulation.sharedSecret.use { shared ->
            crypto.derivations.hkdf(
                inputKey = shared,
                salt = ByteString(),
                info = info,
                length = wrap.keyBytes,
                algorithm = recipient.kdf,
            )
        }
        val wrapped = crypto.keyWraps.wrap(kek = SecretKey.of(kek), key = key, algorithm = wrap)
        val reference = References.of(recipient.certificate, recipient.isKeyIdentifierUsed)
        return Der.encode {
            constructed(RecipientCodec.OTHER) {
                objectIdentifier(CmsOids.ORI_KEM)
                sequence {
                    integer(0)
                    writeReference(reference)
                    writeKem(algorithm)
                    octetString(encapsulation.encapsulated)
                    writeHkdf(recipient.kdf)
                    integer(wrap.keyBytes.toLong())
                    recipient.userKeyingMaterial?.let { ukm -> explicit(KEM_UKM) { octetString(ukm) } }
                    writeKeyWrap(wrap)
                    octetString(wrapped)
                }
            }
        }
    }

    private fun keyOf(certificate: Certificate): PublicKey =
        requireNotNull(certificate.publicKey) { "The key of the recipient's certificate is not usable" }

    companion object {
        private val CURVES: Map<EllipticCurve, KeyType> = mapOf(
            EllipticCurve.P256 to KeyType.P256,
            EllipticCurve.P384 to KeyType.P384,
            EllipticCurve.P521 to KeyType.P521,
        )

        fun agreementType(key: PublicKey): KeyType? {
            val curve = key.curve?.let { found -> CURVES[found] }
            val montgomery = KeyType.X25519.takeIf { key.family == KeyFamily.X25519 }
                ?: KeyType.X448.takeIf { key.family == KeyFamily.X448 }
            return curve ?: montgomery
        }

        fun originatorAlgorithm(key: PublicKey): ObjectIdentifier {
            val montgomery = CmsOids.X25519.takeIf { key.family == KeyFamily.X25519 }
                ?: CmsOids.X448.takeIf { key.family == KeyFamily.X448 }
            return montgomery ?: CmsOids.EC_PUBLIC_KEY
        }

        fun isVersionZero(recipient: Recipient): Boolean =
            recipient is Recipient.KeyTransport && !recipient.isKeyIdentifierUsed

        fun isVersionThree(recipient: Recipient): Boolean =
            recipient is Recipient.Password || recipient is Recipient.Kem
    }
}
