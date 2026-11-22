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

package com.davils.krypt.keystore.internal

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerLimits
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readListOf
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.asn1.readText
import kotlinx.io.bytestring.ByteString

private const val VERSION: Int = 3
private const val MAXIMUM_ATTRIBUTES: Int = 16
private const val MAXIMUM_KEY_BYTES: Int = 64
private const val ENCRYPTED_DATA_VERSIONS: Int = 2

internal object Pkcs12Reader {
    private val VALUE_READERS: Map<ObjectIdentifier, DerReader.() -> BagValue> = mapOf(
        Pkcs12Oids.KEY_BAG to { BagValue.Key(readElement(Tag.Sequence).encoded, isEncrypted = false) },
        Pkcs12Oids.SHROUDED_KEY_BAG to { BagValue.Key(readElement(Tag.Sequence).encoded, isEncrypted = true) },
        Pkcs12Oids.CERTIFICATE_BAG to { readCertificateBag() },
    )

    private val CONTENT_READERS: Map<ObjectIdentifier, DerReader.() -> SafeContent> = mapOf(
        Pkcs12Oids.DATA to { SafeContent.Plain(readOctetString()) },
        Pkcs12Oids.ENCRYPTED_DATA to { readSequence { readEncryptedData() } },
    )

    private val ATTRIBUTE_READERS: Map<ObjectIdentifier, DerReader.() -> BagAttributes> = mapOf(
        Pkcs12Oids.FRIENDLY_NAME to { BagAttributes(friendlyName = readText(Tag.BmpString)) },
        Pkcs12Oids.LOCAL_KEY_ID to { BagAttributes(localKeyId = readOctetString()) },
        Pkcs12Oids.TRUSTED_KEY_USAGE to { trusted() },
    )

    fun pfx(bytes: ByteString, limits: DerLimits): PfxParts? = Der.decodeOrNull(bytes, limits) {
        readSequence {
            readInt(VERSION..VERSION)
            val authenticated = readSequence {
                expect(readObjectIdentifier() == Pkcs12Oids.DATA, "data")
                readExplicit(0) { readOctetString() }
            }
            val mac = Tag.Sequence.takeIf { tag -> isNext(tag) }?.let { readMacData() }
            PfxParts(authenticated = authenticated, mac = mac)
        }
    }

    fun contents(bytes: ByteString, limits: DerLimits, maximum: Int): List<SafeContent>? =
        Der.decodeOrNull(bytes, limits) {
            readListOf(maximum) {
                readSequence {
                    val type = readObjectIdentifier()
                    readExplicit(0) { readContent(type) }
                }
            }
        }

    fun bags(bytes: ByteString, limits: DerLimits, maximum: Int): List<SafeBag>? = Der.decodeOrNull(bytes, limits) {
        readListOf(maximum) { readSequence { readBag() } }
    }

    fun iterationsOf(algorithm: ByteString): Int? = Der.decodeOrNull(algorithm) { readSequence { readIterations() } }

    fun shroudedIterationsOf(encrypted: ByteString): Int? = Der.decodeOrNull(encrypted) {
        readSequence {
            val iterations = readSequence { readIterations() }
            readRemaining()
            iterations
        }
    }

    private fun DerReader.readIterations(): Int {
        val isPbes2 = readObjectIdentifier() == Pkcs12Oids.PBES2
        val iterations = when (isPbes2) {
            true -> readSequence { readPbes2Iterations() }
            false -> 0
        }
        readRemaining()
        return iterations
    }

    private fun DerReader.readPbes2Iterations(): Int {
        val iterations = readSequence {
            expect(readObjectIdentifier() == Pkcs12Oids.PBKDF2, "PBKDF2")
            readSequence {
                readOctetString()
                readInt(1..Int.MAX_VALUE).also { readRemaining() }
            }
        }
        readRemaining()
        return iterations
    }

    private fun DerReader.readMacData(): MacParts = readSequence {
        val (algorithm, tag) = readSequence { readElement(Tag.Sequence).encoded to readOctetString() }
        val salt = readOctetString()
        val iterations = Tag.Integer.takeIf { integer -> isNext(integer) }?.let { readInt(1..Int.MAX_VALUE) } ?: 1
        val parts = Der.decodeOrNull(algorithm) {
            readSequence { readMacAlgorithm(tag = tag, salt = salt, iterations = iterations) }
        }
        parts ?: refuse(DerFailure.InvalidValue, "a MAC algorithm")
    }

    private fun DerReader.readMacAlgorithm(tag: ByteString, salt: ByteString, iterations: Int): MacParts {
        val algorithm = readObjectIdentifier()
        if (algorithm == Pkcs12Oids.PBMAC1) return readSequence { readPbmac1(tag) }
        readRemaining()
        return MacParts.Classic(
            digest = Pkcs12Oids.DIGESTS[algorithm],
            tag = tag,
            salt = salt,
            iterations = iterations,
        )
    }

    private fun DerReader.readPbmac1(tag: ByteString): MacParts {
        val kdf = readSequence {
            expect(readObjectIdentifier() == Pkcs12Oids.PBKDF2, "PBKDF2")
            readSequence { readPbkdf2() }
        }
        val mac = readSequence { readHmac() }
        return MacParts.Pbmac1(
            kdf = kdf.digest,
            salt = kdf.salt,
            iterations = kdf.iterations,
            keyBytes = kdf.keyBytes,
            mac = mac,
            tag = tag,
        )
    }

    private fun DerReader.readPbkdf2(): Pbkdf2Parts {
        val salt = readOctetString()
        val iterations = readInt(1..Int.MAX_VALUE)
        val keyBytes = readInt(1..MAXIMUM_KEY_BYTES)
        val digest = Tag.Sequence.takeIf { sequence -> isNext(sequence) }?.let { readSequence { readHmac() } }
        return Pbkdf2Parts(salt = salt, iterations = iterations, keyBytes = keyBytes, digest = digest?.digest)
    }

    private fun DerReader.readHmac() = Pkcs12Oids.HMACS[readObjectIdentifier()].also { readRemaining() }

    private fun DerReader.readContent(type: ObjectIdentifier): SafeContent {
        val reader = CONTENT_READERS[type] ?: { foreign() }
        return reader()
    }

    private fun DerReader.readEncryptedData(): SafeContent {
        readInt(0..ENCRYPTED_DATA_VERSIONS)
        val content = readSequence {
            expect(readObjectIdentifier() == Pkcs12Oids.DATA, "data")
            val algorithm = readElement(Tag.Sequence).encoded
            val ciphertext = readElement(Tag.context(number = 0, isConstructed = false)).content
            SafeContent.Encrypted(algorithm = algorithm, ciphertext = ciphertext)
        }
        readOptional(Tag.context(number = 1, isConstructed = true))
        return content
    }

    private fun DerReader.readBag(): SafeBag {
        val type = readObjectIdentifier()
        val reader = VALUE_READERS[type] ?: { skipped() }
        val value = readExplicit(0) { reader() }
        val attributes = Tag.Set.takeIf { set -> isNext(set) }?.let {
            readListOf(MAXIMUM_ATTRIBUTES, Tag.Set) { readSequence { readAttribute() } }
        }
        val merged = attributes.orEmpty().fold(BagAttributes()) { all, attribute ->
            merged(first = all, second = attribute)
        }
        return SafeBag(value = value, attributes = merged)
    }

    private fun DerReader.readCertificateBag(): BagValue = readSequence {
        val type = readObjectIdentifier()
        val encoded = readExplicit(0) { readOctetString() }
        encoded.takeIf { type == Pkcs12Oids.X509_CERTIFICATE }?.let { certificate -> BagValue.Cert(certificate) }
            ?: BagValue.Skipped
    }

    private fun DerReader.readAttribute(): BagAttributes {
        val type = readObjectIdentifier()
        val reader = ATTRIBUTE_READERS[type] ?: { ignored() }
        return readSet { reader() }
    }

    private fun DerReader.foreign(): SafeContent {
        readRemaining()
        return SafeContent.Foreign
    }

    private fun DerReader.skipped(): BagValue {
        readElement()
        return BagValue.Skipped
    }

    private fun DerReader.ignored(): BagAttributes {
        readRemaining()
        return BagAttributes()
    }

    private fun merged(first: BagAttributes, second: BagAttributes): BagAttributes = BagAttributes(
        friendlyName = first.friendlyName ?: second.friendlyName,
        localKeyId = first.localKeyId ?: second.localKeyId,
        isTrusted = first.isTrusted || second.isTrusted,
    )

    private fun DerReader.trusted(): BagAttributes {
        readRemaining()
        return BagAttributes(isTrusted = true)
    }

    private fun DerReader.expect(isValid: Boolean, detail: String) {
        if (!isValid) refuse(DerFailure.InvalidValue, detail)
    }
}
