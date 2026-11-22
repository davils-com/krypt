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

package com.davils.krypt.storage.record

import com.davils.krypt.keyset.KeysetAead
import com.davils.krypt.storage.internal.Texts
import kotlinx.io.bytestring.ByteString

private const val LABEL: String = "krypt record v1"

/**
 * Encrypts single fields of records, such as columns of a database, with a key set, bound to their [RecordContext].
 *
 * Every value gets a fresh nonce, so equal values give different ciphertexts; search them with a [BlindIndex]. The
 * ciphertext names the key that encrypted it, so the key set rotates without touching old values. The object is safe
 * to share between threads.
 *
 * @property aead the encryption of the key set, such as one of [com.davils.krypt.storage.SubjectKeys] for data that
 *   must be shredded per person.
 * @constructor Encrypts with [aead].
 * @since 1.0.0
 */
public class RecordCipher(public val aead: KeysetAead) {
    /**
     * Encrypts [value] for [context].
     *
     * @param value the value.
     * @param context where the value lives.
     * @return the ciphertext.
     * @since 1.0.0
     */
    public suspend fun encrypt(value: ByteString, context: RecordContext): ByteString =
        aead.encrypt(plaintext = value, associatedData = contextOf(context))

    /**
     * Decrypts a ciphertext of [encrypt] for [context].
     *
     * @param ciphertext the ciphertext, possibly changed or moved.
     * @param context where the value lives.
     * @return the value, or null if the ciphertext was changed, belongs to another field or its key is gone.
     * @since 1.0.0
     */
    public suspend fun decrypt(ciphertext: ByteString, context: RecordContext): ByteString? =
        aead.decrypt(ciphertext = ciphertext, associatedData = contextOf(context))

    /**
     * Encrypts the text [value] for [context] into base64url, for a text column.
     *
     * @param value the text.
     * @param context where the value lives.
     * @return the ciphertext in base64url without padding.
     * @since 1.0.0
     */
    public suspend fun encryptText(value: String, context: RecordContext): String =
        Texts.base64Url(encrypt(value = Texts.utf8(value), context = context))

    /**
     * Decrypts a ciphertext of [encryptText] for [context].
     *
     * @param ciphertext the ciphertext in base64url, possibly changed or moved.
     * @param context where the value lives.
     * @return the text, or null if the ciphertext is not base64url, was changed or belongs to another field.
     * @since 1.0.0
     */
    public suspend fun decryptText(ciphertext: String, context: RecordContext): String? {
        val bytes = Texts.fromBase64Url(ciphertext) ?: return null
        val value = decrypt(ciphertext = bytes, context = context)
        return value?.text()
    }

    /**
     * Shows the key set.
     *
     * @return the cipher as text.
     * @since 1.0.0
     */
    override fun toString(): String = "RecordCipher(${aead.keyset})"

    private fun ByteString.text(): String = toByteArray().decodeToString()

    private fun contextOf(context: RecordContext): ByteString =
        Texts.framed(listOf(LABEL, context.table, context.column, context.row))
}
