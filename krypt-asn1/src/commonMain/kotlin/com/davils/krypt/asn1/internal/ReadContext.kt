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

package com.davils.krypt.asn1.internal

import com.davils.krypt.asn1.DerException
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerLimits

internal class ReadContext(val limits: DerLimits) {
    private var elements = 0

    fun countElement() {
        elements += 1
        if (elements > limits.maximumElements) {
            throw DerException(DerFailure.LimitExceeded, "more than ${limits.maximumElements} elements")
        }
    }

    fun checkDepth(depth: Int) {
        if (depth > limits.maximumDepth) {
            throw DerException(DerFailure.LimitExceeded, "nesting deeper than ${limits.maximumDepth} levels")
        }
    }
}
