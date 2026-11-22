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

package com.davils.krypt.storage.blob

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.io.BufferSink
import com.davils.krypt.core.io.ByteSink
import com.davils.krypt.core.io.ByteSource
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.keyset.KeysetAead
import com.davils.krypt.keyset.KeysetMac
import com.davils.krypt.storage.StorageFailure
import com.davils.krypt.storage.internal.Located
import com.davils.krypt.storage.internal.MetadataCodec
import com.davils.krypt.storage.internal.OffsetSource
import com.davils.krypt.storage.internal.SequentialSource
import com.davils.krypt.storage.internal.StorageRefusal
import com.davils.krypt.storage.internal.StorageRefusal.Companion.refuse
import com.davils.krypt.storage.internal.Texts
import com.davils.krypt.stream.Containers
import com.davils.krypt.stream.Credential
import com.davils.krypt.stream.RandomAccessSource
import com.davils.krypt.stream.Recipient
import com.davils.krypt.stream.StreamFailure
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val DEFAULT_SEGMENT_SIZE: Int = 65_536
private const val DEFAULT_TYPE: String = "application/octet-stream"
private const val LABEL: String = "krypt blob v1 "
private const val MAXIMUM_NAME: Int = 1_024
private const val MAXIMUM_METADATA: Long = 65_536L
private const val PREFIX_BYTES: Int = 9
private const val FORMAT: Byte = 1
private val MAGIC: ByteString = Texts.utf8("KBLB")

/**
 * Keeps objects of any size encrypted in a [BlobStore], so that whole applications can keep their files in storage
 * they do not trust.
 *
 * Every object is a container of `KRYPT/1` for the key set [dataKeys], preceded by its [ObjectMetadata] encrypted with
 * the same key set. The store sees neither names nor metadata: an object is kept under the base64url of a MAC of its
 * name with [names], and found again under every enabled key of that key set. The name is bound to the metadata and
 * the name and the version to the content, so an object moved to another name or swapped with another version is
 * refused. With a [ledger], a version that is older than the one the ledger records is refused as a rollback;
 * without one, an old version that was put back is accepted.
 *
 * The object holds no key of its own and is safe to share between threads; puts of the same name at once are ordered
 * by the store and the ledger.
 *
 * @param containers the containers and their primitives.
 * @param store where the encrypted objects are kept.
 * @property dataKeys the key set whose primary key protects new objects.
 * @property names the key set that blinds the names.
 * @param ledger the trusted record of versions, or null.
 * @property segmentSize the size of a segment of the containers.
 * @constructor Keeps objects in [store].
 * @since 1.0.0
 */
public class EncryptedBlobStore(
    private val containers: Containers,
    private val store: BlobStore,
    public val dataKeys: KeysetAead,
    public val names: KeysetMac,
    private val ledger: VersionLedger? = null,
    public val segmentSize: Int = DEFAULT_SEGMENT_SIZE,
) {
    private val crypto = containers.crypto

    /**
     * Encrypts everything [source] holds as the next version of [name].
     *
     * @param name the name: 1 to 1024 characters.
     * @param source the content.
     * @param contentType the media type; `application/octet-stream` by default.
     * @param attributes further facts, at most 32.
     * @return the metadata of the new version.
     * @throws IllegalArgumentException if [name] or the metadata is invalid.
     * @throws IllegalStateException if the ledger records another version than was read, because of a concurrent put.
     * @since 1.0.0
     */
    public suspend fun put(
        name: String,
        source: ByteSource,
        contentType: String = DEFAULT_TYPE,
        attributes: Map<String, String> = emptyMap(),
    ): ObjectMetadata {
        checkName(name)
        val key = keyOf(name)
        val previous = ledger?.current(key) ?: currentVersion(name)
        val metadata = ObjectMetadata(
            name = name,
            version = (previous ?: 0L) + 1,
            contentType = contentType,
            createdAt = now(),
            attributes = attributes,
        )
        val isRecorded = ledger?.record(key = key, version = metadata.version, expected = previous) != false
        check(isRecorded) { "Another version of the object was put at the same time" }
        val encryptedMetadata = dataKeys.encrypt(
            plaintext = MetadataCodec.encode(metadata),
            associatedData = metadataContext(name),
        )
        store.write(key) { sink ->
            sink.writeBytes(Texts.concat(MAGIC, ByteString(FORMAT), Texts.u32(encryptedMetadata.size.toLong())))
            sink.writeBytes(encryptedMetadata)
            containers.encrypt(
                source = source,
                sink = sink,
                recipients = listOf(Recipient.Key(dataKeys)),
                associatedData = contentContext(metadata),
                segmentSize = segmentSize,
            )
        }
        removeStale(name = name, kept = key)
        return metadata
    }

    /**
     * Encrypts [content] held in memory as the next version of [name].
     *
     * @param name the name.
     * @param content the content.
     * @param contentType the media type.
     * @param attributes further facts.
     * @return the metadata of the new version.
     * @throws IllegalArgumentException if [name] or the metadata is invalid.
     * @since 1.0.0
     */
    public suspend fun put(
        name: String,
        content: ByteString,
        contentType: String = DEFAULT_TYPE,
        attributes: Map<String, String> = emptyMap(),
    ): ObjectMetadata = put(
        name = name,
        source = content.asByteSource(),
        contentType = contentType,
        attributes = attributes,
    )

    /**
     * Returns the metadata of [name] without decrypting its content.
     *
     * @param name the name.
     * @return the metadata, or why it could not be read.
     * @throws IllegalArgumentException if [name] is invalid.
     * @since 1.0.0
     */
    public suspend fun metadata(name: String): Outcome<ObjectMetadata, StorageFailure> = attempt {
        checkName(name)
        found(name).metadata
    }

    /**
     * Decrypts the content of [name] into [sink].
     *
     * @param name the name.
     * @param sink where the content goes; discard it unless the result is a success.
     * @return the metadata, or why the object could not be read.
     * @throws IllegalArgumentException if [name] is invalid.
     * @since 1.0.0
     */
    public suspend fun read(name: String, sink: ByteSink): Outcome<ObjectMetadata, StorageFailure> = attempt {
        checkName(name)
        val located = found(name)
        val decrypted = containers.decrypt(
            source = SequentialSource(located.content),
            sink = sink,
            credentials = listOf(Credential.Key(dataKeys)),
            associatedData = contentContext(located.metadata),
        )
        valueOf(decrypted)
        located.metadata
    }

    /**
     * Decrypts the content of [name] into memory.
     *
     * @param name the name.
     * @return the content, or why the object could not be read.
     * @throws IllegalArgumentException if [name] is invalid.
     * @since 1.0.0
     */
    public suspend fun get(name: String): Outcome<ByteString, StorageFailure> {
        val sink = BufferSink(Int.MAX_VALUE)
        val result = read(name, sink)
        val content = when (result) {
            is Outcome.Success -> Outcome.Success(sink.toByteString())
            is Outcome.Failure -> result
        }
        sink.wipe()
        return content
    }

    /**
     * Opens [name] for reading at any offset.
     *
     * @param name the name.
     * @return the object, which the caller closes, or why it could not be opened.
     * @throws IllegalArgumentException if [name] is invalid.
     * @since 1.0.0
     */
    public suspend fun open(name: String): Outcome<StoredObject, StorageFailure> = attempt {
        checkName(name)
        val located = found(name)
        val opened = containers.open(
            source = located.content,
            credentials = listOf(Credential.Key(dataKeys)),
            associatedData = contentContext(located.metadata),
        )
        StoredObject(metadata = located.metadata, reader = valueOf(opened))
    }

    /**
     * Deletes every copy of [name] and forgets its version in the ledger.
     *
     * @param name the name.
     * @return true if something was deleted.
     * @throws IllegalArgumentException if [name] is invalid.
     * @since 1.0.0
     */
    public suspend fun delete(name: String): Boolean {
        checkName(name)
        val keys = keysOf(name)
        val deleted = keys.map { key -> store.delete(key) }
        keys.forEach { key -> ledger?.forget(key) }
        return deleted.any { isDeleted -> isDeleted }
    }

    /**
     * Moves [name] to the primary keys of [dataKeys] and [names] after a rotation, without encrypting its content
     * again: its data key is wrapped anew and its metadata encrypted anew.
     *
     * @param name the name.
     * @return the metadata, or why the object could not be read.
     * @throws IllegalArgumentException if [name] is invalid.
     * @since 1.0.0
     */
    public suspend fun rewrap(name: String): Outcome<ObjectMetadata, StorageFailure> = attempt {
        checkName(name)
        val located = found(name)
        val metadata = located.metadata
        val key = keyOf(name)
        val encryptedMetadata = dataKeys.encrypt(
            plaintext = MetadataCodec.encode(metadata),
            associatedData = metadataContext(name),
        )
        store.write(key) { sink ->
            sink.writeBytes(Texts.concat(MAGIC, ByteString(FORMAT), Texts.u32(encryptedMetadata.size.toLong())))
            sink.writeBytes(encryptedMetadata)
            val rewrapped = containers.rewrap(
                source = SequentialSource(located.content),
                sink = sink,
                credentials = listOf(Credential.Key(dataKeys)),
                recipients = listOf(Recipient.Key(dataKeys)),
                associatedData = contentContext(metadata),
            )
            valueOf(rewrapped)
        }
        if (key != located.key) ledger?.record(key = key, version = metadata.version, expected = null)
        removeStale(name = name, kept = key)
        metadata
    }

    /**
     * Shows the key sets.
     *
     * @return the store as text.
     * @since 1.0.0
     */
    override fun toString(): String = "EncryptedBlobStore(dataKeys=${dataKeys.keyset}, names=${names.keyset})"

    private suspend fun keyOf(name: String): String = Texts.base64Url(names.compute(Texts.utf8(name)))

    private suspend fun keysOf(name: String): List<String> =
        names.computeAll(Texts.utf8(name)).map { tag -> Texts.base64Url(tag) }

    private suspend fun removeStale(name: String, kept: String) {
        val stale = keysOf(name).filter { key -> key != kept }
        stale.forEach { key ->
            store.delete(key)
            ledger?.forget(key)
        }
    }

    private suspend fun currentVersion(name: String): Long? {
        val located = locate(name) ?: return null
        return located.metadata.version
    }

    private fun now(): Instant {
        val now = crypto.environment.clock.now()
        return Instant.fromEpochMilliseconds(now.toEpochMilliseconds())
    }

    private suspend fun found(name: String): Located = locate(name) ?: refuse(StorageFailure.Missing)

    private suspend fun locate(name: String): Located? {
        for (key in keysOf(name)) {
            val source = store.open(key)
            if (source != null) return parse(key = key, name = name, source = source)
        }
        return null
    }

    private suspend fun parse(key: String, name: String, source: RandomAccessSource): Located {
        val head = source.read(offset = 0L, length = PREFIX_BYTES)
        val isHeader = head.size == PREFIX_BYTES &&
            head.substring(
                startIndex = 0,
                endIndex = MAGIC.size,
            ) == MAGIC &&
            head[MAGIC.size] == FORMAT
        if (!isHeader) refuse(StorageFailure.Malformed)
        val length = Texts.readU32(head, MAGIC.size + 1)
        if (length > MAXIMUM_METADATA || PREFIX_BYTES + length > source.size) refuse(StorageFailure.Malformed)
        val encrypted = source.read(offset = PREFIX_BYTES.toLong(), length = length.toInt())
        val plaintext = dataKeys.decrypt(
            ciphertext = encrypted,
            associatedData = metadataContext(name),
        ) ?: refuse(StorageFailure.DecryptionFailed)
        val metadata = MetadataCodec.decodeOrNull(plaintext) ?: refuse(StorageFailure.Malformed)
        val recorded = ledger?.current(key)
        if (recorded != null && recorded != metadata.version) refuse(StorageFailure.Rollback)
        return Located(key = key, metadata = metadata, content = OffsetSource(source, PREFIX_BYTES + length))
    }

    private fun metadataContext(name: String): ByteString = Texts.concat(Texts.utf8(LABEL), Texts.utf8(name))

    private fun contentContext(metadata: ObjectMetadata): ByteString =
        Texts.concat(Texts.utf8(LABEL), Texts.u64(metadata.version), Texts.utf8(metadata.name))

    private fun checkName(name: String) {
        require(name.length in 1..MAXIMUM_NAME) { "A name has 1 to $MAXIMUM_NAME characters" }
    }

    private fun <T> valueOf(outcome: Outcome<T, StreamFailure>): T = when (outcome) {
        is Outcome.Success -> outcome.value
        is Outcome.Failure -> refuse(FAILURES[outcome.failure] ?: StorageFailure.DecryptionFailed)
    }

    private suspend fun ByteSink.writeBytes(bytes: ByteString) {
        write(source = bytes.toByteArray(), offset = 0, length = bytes.size)
    }

    private suspend fun <T> attempt(block: suspend () -> T): Outcome<T, StorageFailure> = try {
        Outcome.Success(block())
    } catch (refusal: StorageRefusal) {
        Outcome.Failure(refusal.failure)
    }

    private companion object {
        val FAILURES: Map<StreamFailure, StorageFailure> = mapOf(
            StreamFailure.Malformed to StorageFailure.Malformed,
            StreamFailure.Unsupported to StorageFailure.Malformed,
        )
    }
}
