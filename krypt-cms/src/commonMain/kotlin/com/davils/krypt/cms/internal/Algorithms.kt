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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.cms.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerElement
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.cms.enveloped.ContentEncryption
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.x509.AlgorithmIdentifiers.readSignatureAlgorithm
import kotlinx.io.bytestring.ByteString

private const val CBC_IV_BYTES: Int = 16
private const val GCM_NONCE_BYTES: Int = 12
private const val GCM_TAG_BYTES: Int = 16
private const val OAEP_HASH: Int = 0
private const val OAEP_MASK: Int = 1
private const val OAEP_SOURCE: Int = 2

internal object Algorithms {
    private val DIGESTS: Map<ObjectIdentifier, DigestAlgorithm> = mapOf(
        CmsOids.SHA256 to DigestAlgorithm.Sha256,
        CmsOids.SHA384 to DigestAlgorithm.Sha384,
        CmsOids.SHA512 to DigestAlgorithm.Sha512,
    )

    private val DIGEST_OIDS: Map<DigestAlgorithm, ObjectIdentifier> = inverted(DIGESTS)

    private val PKCS1: Map<DigestAlgorithm, SignatureAlgorithm> = mapOf(
        DigestAlgorithm.Sha256 to SignatureAlgorithm.RsaPkcs1Sha256,
        DigestAlgorithm.Sha384 to SignatureAlgorithm.RsaPkcs1Sha384,
        DigestAlgorithm.Sha512 to SignatureAlgorithm.RsaPkcs1Sha512,
    )

    private val CONTENT: Map<ObjectIdentifier, ContentEncryption> = mapOf(
        CmsOids.AES128_CBC to ContentEncryption.Aes128Cbc,
        CmsOids.AES256_CBC to ContentEncryption.Aes256Cbc,
        CmsOids.AES128_GCM to ContentEncryption.Aes128Gcm,
        CmsOids.AES256_GCM to ContentEncryption.Aes256Gcm,
    )

    private val CONTENT_OIDS: Map<ContentEncryption, ObjectIdentifier> = inverted(CONTENT)

    private val WRAPS: Map<ObjectIdentifier, KeyWrapAlgorithm> = mapOf(
        CmsOids.AES128_WRAP to KeyWrapAlgorithm.Aes128Kw,
        CmsOids.AES256_WRAP to KeyWrapAlgorithm.Aes256Kw,
    )

    private val WRAP_OIDS: Map<KeyWrapAlgorithm, ObjectIdentifier> = inverted(WRAPS)

    private val OAEP: Map<DigestAlgorithm, AsymmetricEncryptionAlgorithm> = mapOf(
        DigestAlgorithm.Sha256 to AsymmetricEncryptionAlgorithm.RsaOaepSha256,
        DigestAlgorithm.Sha384 to AsymmetricEncryptionAlgorithm.RsaOaepSha384,
        DigestAlgorithm.Sha512 to AsymmetricEncryptionAlgorithm.RsaOaepSha512,
    )

    private val HKDFS: Map<ObjectIdentifier, KdfAlgorithm> = mapOf(
        CmsOids.HKDF_SHA256 to KdfAlgorithm.HkdfSha256,
        CmsOids.HKDF_SHA384 to KdfAlgorithm.HkdfSha384,
        CmsOids.HKDF_SHA512 to KdfAlgorithm.HkdfSha512,
    )

    private val HKDF_OIDS: Map<KdfAlgorithm, ObjectIdentifier> = inverted(HKDFS)

    private val KEMS: Map<ObjectIdentifier, KemAlgorithm> = mapOf(
        CmsOids.ML_KEM_768 to KemAlgorithm.MlKem768,
        CmsOids.ML_KEM_1024 to KemAlgorithm.MlKem1024,
    )

    private val KEM_OIDS: Map<KemAlgorithm, ObjectIdentifier> = inverted(KEMS)

    fun DerReader.readDigestAlgorithm(): DigestAlgorithm? = readSequence {
        val oid = readObjectIdentifier()
        skipNullParameter()
        val isPlain = isExhausted
        readRemaining()
        DIGESTS[oid]?.takeIf { isPlain }
    }

    fun DerWriter.writeDigestAlgorithm(digest: DigestAlgorithm) {
        val oid = requireNotNull(DIGEST_OIDS[digest]) { "CMS signs with SHA-2, not ${digest.algorithmName}" }
        sequence { objectIdentifier(oid) }
    }

    fun DerWriter.writeShake256() {
        sequence { objectIdentifier(CmsOids.SHAKE256) }
    }

    fun signatureAlgorithmOf(element: DerElement, digest: DigestAlgorithm?): SignatureAlgorithm? {
        val known = Der.decodeOrNull(element.encoded) { readSignatureAlgorithm() }
        val isRsa = Der.decodeOrNull(element.encoded) { readSequence { isRsaEncryption() } } == true
        val rsa = PKCS1[digest].takeIf { isRsa }
        return known ?: rsa
    }

    fun DerReader.readContentAlgorithm(): ContentAlgorithm? = readSequence {
        val encryption = CONTENT[readObjectIdentifier()]
        val iv = encryption?.let { found -> readContentParameters(found) }
        readRemaining()
        iv?.let { parameter -> ContentAlgorithm(encryption, parameter) }
    }

    fun DerWriter.writeContentAlgorithm(algorithm: ContentAlgorithm) {
        sequence {
            objectIdentifier(CONTENT_OIDS.getValue(algorithm.encryption))
            when (algorithm.encryption.isAuthenticated) {
                true -> sequence {
                    octetString(algorithm.iv)
                    integer(GCM_TAG_BYTES.toLong())
                }

                false -> octetString(algorithm.iv)
            }
        }
    }

    fun ivBytes(encryption: ContentEncryption): Int =
        listOf(CBC_IV_BYTES, GCM_NONCE_BYTES)[encryption.isAuthenticated.compareTo(false)]

    fun DerReader.readKeyWrap(): KeyWrapAlgorithm? = readSequence {
        val wrap = WRAPS[readObjectIdentifier()]
        val isPlain = isExhausted
        readRemaining()
        wrap?.takeIf { isPlain }
    }

    fun DerWriter.writeKeyWrap(wrap: KeyWrapAlgorithm) {
        sequence { objectIdentifier(WRAP_OIDS.getValue(wrap)) }
    }

    fun wrapOf(keyBytes: Int): KeyWrapAlgorithm? = KeyWrapAlgorithm.entries.firstOrNull { wrap ->
        wrap.keyBytes == keyBytes
    }

    fun DerReader.readKeyTransport(): AsymmetricEncryptionAlgorithm? = readSequence {
        val isOaep = readObjectIdentifier() == CmsOids.RSAES_OAEP
        val algorithm = takeIf { isOaep }?.readOaepParameters()
        readRemaining()
        algorithm
    }

    fun DerWriter.writeKeyTransport(digest: DigestAlgorithm) {
        sequence {
            objectIdentifier(CmsOids.RSAES_OAEP)
            sequence {
                explicit(OAEP_HASH) { writeDigestAlgorithm(digest) }
                explicit(OAEP_MASK) {
                    sequence {
                        objectIdentifier(CmsOids.MGF1)
                        writeDigestAlgorithm(digest)
                    }
                }
            }
        }
    }

    fun DerReader.readHkdf(): KdfAlgorithm? = readSequence {
        val kdf = HKDFS[readObjectIdentifier()]
        val isPlain = isExhausted
        readRemaining()
        kdf?.takeIf { isPlain }
    }

    fun DerWriter.writeHkdf(kdf: KdfAlgorithm) {
        sequence { objectIdentifier(HKDF_OIDS.getValue(kdf)) }
    }

    fun DerReader.readKem(): KemAlgorithm? = readSequence {
        val kem = KEMS[readObjectIdentifier()]
        val isPlain = isExhausted
        readRemaining()
        kem?.takeIf { isPlain }
    }

    fun DerWriter.writeKem(kem: KemAlgorithm) {
        sequence { objectIdentifier(KEM_OIDS.getValue(kem)) }
    }

    private fun DerReader.isRsaEncryption(): Boolean {
        val isRsa = readObjectIdentifier() == CmsOids.RSA_ENCRYPTION
        skipNullParameter()
        return isRsa && isExhausted
    }

    private fun DerReader.readContentParameters(encryption: ContentEncryption): ByteString? =
        when (encryption.isAuthenticated) {
            true -> readGcmParameters()
            false -> readIv()
        }

    private fun DerReader.readIv(): ByteString {
        val iv = readOctetString()
        if (iv.size != CBC_IV_BYTES) malformed("an IV of $CBC_IV_BYTES bytes")
        return iv
    }

    private fun DerReader.readGcmParameters(): ByteString? = readSequence {
        val nonce = readOctetString()
        val tagBytes = takeUnless { isExhausted }?.readInt(1..GCM_TAG_BYTES)
        nonce.takeIf { nonce.size == GCM_NONCE_BYTES && tagBytes == GCM_TAG_BYTES }
    }

    private fun DerReader.readOaepParameters(): AsymmetricEncryptionAlgorithm? = readSequence {
        val hash = readOptionalExplicit(OAEP_HASH) { readDigestAlgorithm() }
        val mask = readOptionalExplicit(OAEP_MASK) {
            readSequence {
                val isMgf1 = readObjectIdentifier() == CmsOids.MGF1
                readDigestAlgorithm().takeIf { isMgf1 }
            }
        }
        val isEmptyLabel = readOptionalExplicit(OAEP_SOURCE) {
            readSequence {
                val isSpecified = readObjectIdentifier() == CmsOids.P_SPECIFIED
                val label = readOctetString()
                isSpecified && label.size == 0
            }
        } != false
        OAEP[hash]?.takeIf { hash == mask && isEmptyLabel }
    }

    private fun <K, V> inverted(map: Map<K, V>): Map<V, K> = map.entries.associate { (key, value) -> value to key }
}
