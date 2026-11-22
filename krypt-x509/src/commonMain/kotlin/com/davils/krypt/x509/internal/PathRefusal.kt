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

package com.davils.krypt.x509.internal

import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.path.PathFailure

internal class PathRefusal(val failure: PathFailure, val certificate: Certificate) : Exception(failure.name) {
    companion object {
        fun ensure(isValid: Boolean, failure: PathFailure, certificate: Certificate) {
            if (!isValid) throw PathRefusal(failure, certificate)
        }
    }
}
