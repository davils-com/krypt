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

import com.davils.kore.core.failure.attempted
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
private const val CONCURRENT_PUT: String = "Another version of the object was put at the same time"
private val MAGIC: ByteString = Texts.utf8("KBLB")

/**
 * Keeps objects of any size encrypted in a [BlobStore], so that whole applications can keep their files in storage
 * they do not trust.
 *
 * Every object is a container of `KRYPT/1` for the key set [dataKeys], preceded by its [ObjectMetadata] encrypted with
 * the same key set. The store sees neither names nor metadata: an object is kept under the base64url of a MAC of its
 * name with the primary key of [names], and found again under every enabled key of that key set, the primary key
 * first. The name is bound to the metadata and the name and the version to the content, so an object moved to another
 * name or swapped with another version is refused.
 *
 * **Without a [ledger]** the store alone decides which version is current: whoever controls it can put back an old
 * version of an object, or an object that was deleted, under any blinded key of its name, and it is read as current.
 * Only objects of krypt under their own name are accepted, never forged or moved ones.
 *
 * **With a [ledger]** the ledger is the authority on versions. Every put records the next version before the object is
 * written; a deletion records a version past the deleted one, so versions of a name keep growing and a deleted object
 * that reappears is refused; a [rewrap] carries the version to the blinded key of the new primary key of [names]
 * before the old object is removed. An object is read only if the highest version the ledger records under the
 * blinded keys of its name is exactly its version; every other object, under whichever blinded key it is found, is
 * refused as [StorageFailure.Rollback]. That includes an object whose name the ledger has no record of, such as one
 * put before the ledger was used: put it again. An object whose write failed after its version was recorded also reads
 * as a rollback until it is put again. The guarantee holds as long as every writer uses the same key sets and keeps
 * the key of [names] an object is stored under enabled until the object is rewrapped.
 *
 * **Failures.** The store and the ledger are the code of the application: in [metadata], [read], [get], [open] and
 * [rewrap] what they throw is contained and becomes [StorageFailure.Unavailable]; in [put] and [delete] it is passed
 * on as it was thrown. A cancellation of the caller always passes on.
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
     * The next version follows the highest version the ledger records for [name]; without a ledger it follows the
     * version of the object the store holds, and an object that cannot be read counts as none.
     *
     * @param name the name: 1 to 1024 characters.
     * @param source the content.
     * @param contentType the media type; `application/octet-stream` by default.
     * @param attributes further facts, at most 32.
     * @return the metadata of the new version.
     * @throws IllegalArgumentException if [name] or the metadata is invalid.
     * @throws IllegalStateException if the ledger records another version than was read, because of a concurrent put.
     * @throws Exception what the store or the ledger threw, as it was thrown.
     * @since 1.0.0
     */
    public suspend fun put(
        name: String,
        source: ByteSource,
        contentType: String = DEFAULT_TYPE,
        attributes: Map<String, String> = emptyMap(),
    ): ObjectMetadata {
        checkName(name)
        val keys = keysOf(name)
        val key = keys.first()
        val previous = highest(keys) ?: readableVersion(name, keys)
        val metadata = ObjectMetadata(
            name = name,
            version = (previous ?: 0L) + 1,
            contentType = contentType,
            createdAt = now(),
            attributes = attributes,
        )
        check(recorded(key = key, version = metadata.version)) { CONCURRENT_PUT }
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
        removeStale(keys = keys, kept = key)
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
     * @throws IllegalStateException if the ledger records another version than was read, because of a concurrent put.
     * @throws Exception what the store or the ledger threw, as it was thrown.
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
    public suspend fun metadata(name: String): Outcome<ObjectMetadata, StorageFailure> {
        checkName(name)
        return attempt { verified(name, keysOf(name)).metadata }
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
    public suspend fun read(name: String, sink: ByteSink): Outcome<ObjectMetadata, StorageFailure> {
        checkName(name)
        return attempt {
            val located = verified(name, keysOf(name))
            val decrypted = containers.decrypt(
                source = SequentialSource(located.content),
                sink = sink,
                credentials = listOf(Credential.Key(dataKeys)),
                associatedData = contentContext(located.metadata),
            )
            valueOf(decrypted)
            located.metadata
        }
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
    public suspend fun open(name: String): Outcome<StoredObject, StorageFailure> {
        checkName(name)
        return attempt {
            val located = verified(name, keysOf(name))
            val opened = containers.open(
                source = located.content,
                credentials = listOf(Credential.Key(dataKeys)),
                associatedData = contentContext(located.metadata),
            )
            StoredObject(metadata = located.metadata, reader = valueOf(opened))
        }
    }

    /**
     * Deletes every copy of [name]. With a ledger, a version past the deleted one is recorded first, so that the
     * deleted object is refused if it reappears and the next put continues after it.
     *
     * @param name the name.
     * @return true if something was deleted.
     * @throws IllegalArgumentException if [name] is invalid.
     * @throws IllegalStateException if the ledger records another version than was read, because of a concurrent put;
     *   nothing is deleted then.
     * @throws Exception what the store or the ledger threw, as it was thrown; nothing is deleted if the ledger failed.
     * @since 1.0.0
     */
    public suspend fun delete(name: String): Boolean {
        checkName(name)
        val keys = keysOf(name)
        val key = keys.first()
        if (ledger != null) {
            val previous = highest(keys) ?: readableVersion(name, keys) ?: 0L
            check(recorded(key = key, version = previous + 1)) { CONCURRENT_PUT }
        }
        val deleted = keys.map { found -> store.delete(found) }
        removeStale(keys = keys, kept = key)
        return deleted.any { isDeleted -> isDeleted }
    }

    /**
     * Moves [name] to the primary keys of [dataKeys] and [names] after a rotation, without encrypting its content
     * again: its data key is wrapped anew and its metadata encrypted anew. With a ledger, the version is recorded
     * under the new blinded key before the object under the old one is removed.
     *
     * @param name the name.
     * @return the metadata, or why the object could not be read; [StorageFailure.Unavailable] also if another
     *   version was put at the same time.
     * @throws IllegalArgumentException if [name] is invalid.
     * @since 1.0.0
     */
    public suspend fun rewrap(name: String): Outcome<ObjectMetadata, StorageFailure> {
        checkName(name)
        return attempt {
            val keys = keysOf(name)
            val located = verified(name, keys)
            val metadata = located.metadata
            val key = keys.first()
            val isCarried = key == located.key || recorded(key = key, version = metadata.version)
            if (!isCarried) refuse(StorageFailure.Unavailable)
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
            removeStale(keys = keys, kept = key)
            metadata
        }
    }

    /**
     * Shows the key sets.
     *
     * @return the store as text.
     * @since 1.0.0
     */
    override fun toString(): String = "EncryptedBlobStore(dataKeys=${dataKeys.keyset}, names=${names.keyset})"

    private suspend fun keysOf(name: String): List<String> =
        names.computeAll(Texts.utf8(name)).map { tag -> Texts.base64Url(tag) }

    private suspend fun highest(keys: List<String>): Long? {
        val found = ledger ?: return null
        val versions = keys.mapNotNull { key -> found.current(key) }
        return versions.maxOrNull()
    }

    private suspend fun recorded(key: String, version: Long): Boolean {
        val found = ledger ?: return true
        return found.record(key = key, version = version, expected = found.current(key))
    }

    private suspend fun readableVersion(name: String, keys: List<String>): Long? {
        val located = try {
            locate(name, keys)
        } catch (ignored: StorageRefusal) {
            null
        }
        val metadata = located?.metadata
        return metadata?.version
    }

    private suspend fun removeStale(keys: List<String>, kept: String) {
        val stale = keys.filter { key -> key != kept }
        stale.forEach { key ->
            store.delete(key)
            ledger?.forget(key)
        }
    }

    private fun now(): Instant {
        val now = crypto.environment.clock.now()
        return Instant.fromEpochMilliseconds(now.toEpochMilliseconds())
    }

    private suspend fun verified(name: String, keys: List<String>): Located {
        val located = locate(name, keys) ?: refuse(StorageFailure.Missing)
        val isCurrent = ledger == null || highest(keys) == located.metadata.version
        if (!isCurrent) refuse(StorageFailure.Rollback)
        return located
    }

    private suspend fun locate(name: String, keys: List<String>): Located? {
        for (key in keys) {
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

    private suspend fun <T> attempt(block: suspend () -> T): Outcome<T, StorageFailure> {
        val result = attempted { block() }
        return result.fold(
            onSuccess = { value -> Outcome.Success(value) },
            onFailure = { failure -> Outcome.Failure(failureOf(failure)) },
        )
    }

    private fun failureOf(failure: Throwable): StorageFailure {
        val refusal = failure as? StorageRefusal ?: return StorageFailure.Unavailable
        return refusal.failure
    }

    private companion object {
        val FAILURES: Map<StreamFailure, StorageFailure> = mapOf(
            StreamFailure.Malformed to StorageFailure.Malformed,
            StreamFailure.Unsupported to StorageFailure.Malformed,
        )
    }
}
