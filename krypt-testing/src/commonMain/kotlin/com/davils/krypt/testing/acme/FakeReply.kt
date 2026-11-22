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

package com.davils.krypt.testing.acme

import com.davils.krypt.jose.JsonValue
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

internal data class FakeReply(
    val status: Int,
    val body: ByteString = ByteString(),
    val headers: List<Pair<String, String>> = emptyList(),
) {
    companion object {
        const val OK: Int = 200
        const val CREATED: Int = 201
        const val BAD_REQUEST: Int = 400
        const val UNAUTHORIZED: Int = 401
        const val FORBIDDEN: Int = 403
        const val NOT_FOUND: Int = 404
        const val CONFLICT: Int = 409
        const val CONTENT_TYPE: String = "Content-Type"
        const val LOCATION: String = "Location"

        fun json(json: JsonValue.Object, status: Int = OK, location: String? = null): FakeReply = FakeReply(
            status = status,
            body = json.encode().encodeToByteString(),
            headers = listOfNotNull(CONTENT_TYPE to "application/json", location?.let { found -> LOCATION to found }),
        )
    }
}
