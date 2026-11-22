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

package com.davils.krypt.keyset.fixture

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerWriter
import kotlinx.io.bytestring.ByteString

internal val ID: ByteString = ByteString(1, 2, 3, 4, 5, 6, 7, 8)
internal val OTHER_ID: ByteString = ByteString(8, 7, 6, 5, 4, 3, 2, 1)

internal fun keysetOf(
    names: List<String>,
    entries: List<RawEntry>,
    primary: ByteString = ID,
    version: Long = 1L,
): ByteString = Der.encode {
    sequence {
        integer(version)
        sequence { names.forEach { name -> utf8String(name) } }
        octetString(primary)
        sequence { entries.forEach { entry -> writeEntry(entry) } }
    }
}

internal fun encryptedOf(keyUri: String, ciphertext: ByteString): ByteString = Der.encode {
    sequence {
        integer(1L)
        utf8String(keyUri)
        octetString(ciphertext)
    }
}

private fun DerWriter.writeEntry(entry: RawEntry) {
    sequence {
        octetString(entry.id)
        integer(entry.status)
        integer(0L)
        entry.secret?.let { secret -> explicit(0) { octetString(secret) } }
        entry.privateKey?.let { private -> explicit(1) { octetString(private) } }
        entry.publicKey?.let { public -> explicit(2) { octetString(public) } }
    }
}
