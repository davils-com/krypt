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

package com.davils.krypt.cose.internal

import com.davils.krypt.cose.CoseFailure
import com.davils.krypt.cose.internal.CoseException.Companion.ensure
import com.davils.krypt.cose.internal.CoseException.Companion.present
import kotlinx.io.bytestring.ByteString

internal object Payloads {
    fun of(attached: ByteString?, detached: ByteString?): ByteString {
        val isSingle = attached == null || detached == null
        ensure(isSingle, CoseFailure.Malformed)
        return present(attached ?: detached, CoseFailure.Malformed)
    }
}
