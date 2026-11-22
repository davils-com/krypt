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

import com.davils.krypt.acme.AcmeProblemType

internal class FakeRefusal(val type: AcmeProblemType, val status: Int) : IllegalStateException(type.code)

internal fun refuse(type: AcmeProblemType, status: Int = FakeReply.BAD_REQUEST): Nothing =
    throw FakeRefusal(type, status)

internal fun refuseUnless(
    condition: Boolean,
    type: AcmeProblemType = AcmeProblemType.Malformed,
    status: Int = FakeReply.BAD_REQUEST,
) {
    if (!condition) refuse(type = type, status = status)
}

internal fun <T : Any> present(
    value: T?,
    type: AcmeProblemType = AcmeProblemType.Malformed,
    status: Int = FakeReply.BAD_REQUEST,
): T = value ?: refuse(type = type, status = status)
