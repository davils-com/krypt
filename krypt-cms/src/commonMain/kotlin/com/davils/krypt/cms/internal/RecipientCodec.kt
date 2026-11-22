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

import com.davils.krypt.asn1.DerElement
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.cms.CertificateReference
import com.davils.krypt.cms.enveloped.RecipientInfo
import com.davils.krypt.cms.enveloped.RecipientType
import com.davils.krypt.cms.internal.Algorithms.readContentAlgorithm
import com.davils.krypt.cms.internal.Algorithms.readHkdf
import com.davils.krypt.cms.internal.Algorithms.readKem
import com.davils.krypt.cms.internal.Algorithms.readKeyTransport
import com.davils.krypt.cms.internal.Algorithms.readKeyWrap
import com.davils.krypt.cms.internal.References.readRecipientKeyReference
import com.davils.krypt.cms.internal.References.readReference
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.algorithm.DigestAlgorithm
import kotlinx.io.bytestring.ByteString

private const val KEY_TRANSPORT_VERSIONS: Int = 2
private const val AGREEMENT_VERSION: Int = 3
private const val KEK_VERSION: Int = 4
private const val MAXIMUM_KEK_LENGTH: Int = 65_535
private const val ORIGINATOR: Int = 0
private const val UKM: Int = 1
private const val ORIGINATOR_KEY: Int = 1
private const val KEM_UKM: Int = 0
private const val MINIMUM_SALT: Int = 16
private const val MINIMUM_LEGACY_SALT: Int = 8

internal object RecipientCodec {
    val AGREEMENT: Tag = Tag.context(number = 1, isConstructed = true)
    val KEK: Tag = Tag.context(number = 2, isConstructed = true)
    val PASSWORD: Tag = Tag.context(number = 3, isConstructed = true)
    val OTHER: Tag = Tag.context(number = 4, isConstructed = true)
    val DERIVATION: Tag = Tag.context(number = 0, isConstructed = true)

    private val SCHEMES: Map<ObjectIdentifier, ParsedRecipient.AgreementScheme> = mapOf(
        CmsOids.ECDH_SHA256 to ParsedRecipient.AgreementScheme(DigestAlgorithm.Sha256, isHkdf = false),
        CmsOids.ECDH_SHA384 to ParsedRecipient.AgreementScheme(DigestAlgorithm.Sha384, isHkdf = false),
        CmsOids.ECDH_SHA512 to ParsedRecipient.AgreementScheme(DigestAlgorithm.Sha512, isHkdf = false),
        CmsOids.ECDH_COFACTOR_SHA256 to ParsedRecipient.AgreementScheme(DigestAlgorithm.Sha256, isHkdf = false),
        CmsOids.ECDH_COFACTOR_SHA384 to ParsedRecipient.AgreementScheme(DigestAlgorithm.Sha384, isHkdf = false),
        CmsOids.ECDH_COFACTOR_SHA512 to ParsedRecipient.AgreementScheme(DigestAlgorithm.Sha512, isHkdf = false),
        CmsOids.HKDF_SCHEME_SHA256 to ParsedRecipient.AgreementScheme(DigestAlgorithm.Sha256, isHkdf = true),
        CmsOids.HKDF_SCHEME_SHA384 to ParsedRecipient.AgreementScheme(DigestAlgorithm.Sha384, isHkdf = true),
        CmsOids.HKDF_SCHEME_SHA512 to ParsedRecipient.AgreementScheme(DigestAlgorithm.Sha512, isHkdf = true),
    )

    private val PRFS: Map<ObjectIdentifier, DigestAlgorithm> = mapOf(
        CmsOids.HMAC_SHA1 to DigestAlgorithm.Sha1,
        CmsOids.HMAC_SHA256 to DigestAlgorithm.Sha256,
        CmsOids.HMAC_SHA512 to DigestAlgorithm.Sha512,
    )

    private val COFACTOR: Set<ObjectIdentifier> =
        setOf(CmsOids.ECDH_COFACTOR_SHA256, CmsOids.ECDH_COFACTOR_SHA384, CmsOids.ECDH_COFACTOR_SHA512)

    val SCHEME_OIDS: Map<ParsedRecipient.AgreementScheme, ObjectIdentifier> =
        SCHEMES.entries.filter { (oid, _) -> oid !in COFACTOR }.associate { (oid, scheme) -> scheme to oid }

    val PRF_OIDS: Map<DigestAlgorithm, ObjectIdentifier> = PRFS.entries.associate { (oid, digest) -> digest to oid }

    fun recipientOf(element: DerElement, maximum: Int): RecipientInfo {
        val tag = element.tag
        val parsed = element.takeIf { tag == Tag.Sequence }?.parse(Tag.Sequence) { readTransport() }
            ?: element.takeIf { tag == AGREEMENT }?.parse(AGREEMENT) { readAgreement(maximum) }
            ?: element.takeIf { tag == KEK }?.parse(KEK) { readKek() }
            ?: element.takeIf { tag == PASSWORD }?.parse(PASSWORD) { readPassword() }
            ?: element.takeIf { tag == OTHER }?.parse(OTHER) { readOther() }
            ?: malformed("a RecipientInfo")
        return RecipientInfo(parsed = parsed, encoded = element.encoded)
    }

    private fun DerReader.readTransport(): ParsedRecipient {
        val version = readInt(0..KEY_TRANSPORT_VERSIONS)
        val reference = readReference()
        val isKeyIdentifier = reference is CertificateReference.KeyIdentifier
        val expected = listOf(0, KEY_TRANSPORT_VERSIONS)[isKeyIdentifier.compareTo(false)]
        if (version != expected) malformed("version $expected of a key transport recipient")
        val algorithm = readKeyTransport()
        val encryptedKey = readOctetString()
        val transport = algorithm?.let { found ->
            ParsedRecipient.Transport(reference = reference, algorithm = found, encryptedKey = encryptedKey)
        }
        return transport ?: unsupported(RecipientType.KeyTransport, listOf(reference))
    }

    private fun DerReader.readAgreement(maximum: Int): ParsedRecipient {
        readInt(AGREEMENT_VERSION..AGREEMENT_VERSION)
        val originator = readExplicit(ORIGINATOR) { readOriginator() }
        val ukm = readOptionalExplicit(UKM) { readOctetString() }
        val (scheme, wrap) = readSequence {
            val scheme = SCHEMES[readObjectIdentifier()]
            val wrap = takeIf { isNext(Tag.Sequence) }?.readKeyWrap()
            readRemaining()
            scheme to wrap
        }
        val keys = readSequence {
            val all = mutableListOf<Pair<CertificateReference, ByteString>>()
            while (!isExhausted) {
                if (all.size >= maximum) limited("at most $maximum recipient keys")
                all += readSequence { readRecipientKeyReference() to readOctetString() }
            }
            all
        }
        if (keys.isEmpty()) malformed("a recipient key")
        if (originator == null || scheme == null || wrap == null) {
            return unsupported(RecipientType.KeyAgreement, keys.map { (reference, _) -> reference })
        }
        return ParsedRecipient.Agreement(
            originatorAlgorithm = originator.first,
            originatorKey = originator.second,
            userKeyingMaterial = ukm,
            scheme = scheme,
            wrap = wrap,
            keys = keys,
        )
    }

    private fun DerReader.readOriginator(): Pair<ObjectIdentifier, ByteString>? {
        val tag = Tag.context(number = ORIGINATOR_KEY, isConstructed = true)
        val element = readElement()
        return element.takeIf { found -> found.tag == tag }?.parse(tag) {
            val algorithm = readSequence {
                val oid = readObjectIdentifier()
                readRemaining()
                oid
            }
            val bits = readBitString()
            if (bits.unusedBits != 0) malformed("a public key of whole bytes")
            algorithm to bits.bytes
        }
    }

    private fun DerReader.readKek(): ParsedRecipient {
        readInt(KEK_VERSION..KEK_VERSION)
        val identifier = readSequence {
            val value = readOctetString()
            readRemaining()
            value
        }
        val wrap = readKeyWrap()
        val encryptedKey = readOctetString()
        val kek = wrap?.let { found ->
            ParsedRecipient.Kek(keyIdentifier = identifier, wrap = found, encryptedKey = encryptedKey)
        }
        return kek ?: ParsedRecipient.Unsupported(RecipientType.Kek, emptyList(), identifier)
    }

    private fun DerReader.readPassword(): ParsedRecipient {
        readInt(0..0)
        val derivation = readOptional(DERIVATION)?.parse(DERIVATION) { readPbkdf2() }
        val cipher = readSequence {
            val isPwriKek = readObjectIdentifier() == CmsOids.PWRI_KEK
            val algorithm = takeIf { isPwriKek }?.readContentAlgorithm()
            readRemaining()
            algorithm?.takeUnless { found -> found.encryption.isAuthenticated }
        }
        val encryptedKey = readOctetString()
        val found = derivation?.first
        val length = derivation?.second
        val isUsable = found != null && cipher != null && (length == null || length == cipher.encryption.keyBytes)
        if (!isUsable) return unsupported(RecipientType.Password, emptyList())
        return ParsedRecipient.Password(derivation = found, cipher = cipher, encryptedKey = encryptedKey)
    }

    private fun DerReader.readPbkdf2(): Pair<ParsedRecipient.PasswordDerivation?, Int?> {
        val isPbkdf2 = readObjectIdentifier() == CmsOids.PBKDF2
        val derivation = takeIf { isPbkdf2 }?.readSequence {
            val salt = readOctetString()
            val iterations = readInt(1..Int.MAX_VALUE)
            val keyBytes = takeIf { isNext(Tag.Integer) }?.readInt(1..Int.MAX_VALUE)
            val prf = when (isExhausted) {
                true -> DigestAlgorithm.Sha1
                false -> readSequence { readPrf() }
            }
            val minimum = listOf(MINIMUM_SALT, MINIMUM_LEGACY_SALT)[(prf == DigestAlgorithm.Sha1).compareTo(false)]
            val usable = prf?.takeIf { salt.size >= minimum }?.let { found ->
                ParsedRecipient.PasswordDerivation(salt = salt, iterations = iterations, prf = found)
            }
            usable to keyBytes
        }
        readRemaining()
        return derivation ?: (null to null)
    }

    private fun DerReader.readPrf(): DigestAlgorithm? {
        val digest = PRFS[readObjectIdentifier()]
        skipNullParameter()
        readRemaining()
        return digest
    }

    private fun DerReader.readOther(): ParsedRecipient {
        val isKem = readObjectIdentifier() == CmsOids.ORI_KEM
        val kem = takeIf { isKem }?.readSequence { readKemRecipient() }
        readRemaining()
        return kem ?: unsupported(RecipientType.Other, emptyList())
    }

    private fun DerReader.readKemRecipient(): ParsedRecipient {
        readInt(0..0)
        val reference = readReference()
        val kem = readKem()
        val ciphertext = readOctetString()
        val kdf = readHkdf()
        val kekLength = readInt(1..MAXIMUM_KEK_LENGTH)
        val ukm = readOptionalExplicit(KEM_UKM) { readOctetString() }
        val wrap = readKeyWrap()?.takeIf { found -> found.keyBytes == kekLength }
        val encryptedKey = readOctetString()
        if (kem == null || kdf == null || wrap == null) return unsupported(RecipientType.Kem, listOf(reference))
        return ParsedRecipient.Kem(
            reference = reference,
            kem = kem,
            ciphertext = ciphertext,
            kdf = kdf,
            userKeyingMaterial = ukm,
            wrap = wrap,
            encryptedKey = encryptedKey,
        )
    }

    private fun unsupported(type: RecipientType, references: List<CertificateReference>): ParsedRecipient =
        ParsedRecipient.Unsupported(type = type, references = references, keyIdentifier = null)
}
