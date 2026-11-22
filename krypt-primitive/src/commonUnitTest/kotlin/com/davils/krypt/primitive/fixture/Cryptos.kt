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

package com.davils.krypt.primitive.fixture

import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto

private const val FAST_ITERATIONS: Int = 1_000

internal val crypto: Crypto = Crypto()

internal val fastCrypto: Crypto = Crypto(
    environment {
        policy = cryptoPolicy {
            minimumIterations = FAST_ITERATIONS
            minimumVerifiedIterations = FAST_ITERATIONS
        }
    },
)
