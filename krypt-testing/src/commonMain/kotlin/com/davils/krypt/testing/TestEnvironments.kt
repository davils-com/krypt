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

package com.davils.krypt.testing

import com.davils.kore.testing.TestClock
import com.davils.krypt.core.Environment
import com.davils.krypt.core.EnvironmentBuilder
import com.davils.krypt.core.environment
import com.davils.krypt.primitive.Crypto
import kotlin.time.Clock

private const val DEFAULT_SEED: Long = 42L

/**
 * Returns an environment for tests: the time of [clock] and the deterministic randomness of [seed].
 *
 * @param clock the clock of certificates, tokens and audit entries; a [TestClock] at the epoch by default.
 * @param seed the seed of the randomness; 42 by default.
 * @param configure changes what else differs, such as the policy or `audit(log)`.
 * @return the environment.
 * @since 1.0.0
 */
public fun testEnvironment(
    clock: Clock = TestClock(),
    seed: Long = DEFAULT_SEED,
    configure: EnvironmentBuilder.() -> Unit = {},
): Environment = environment {
    this.clock = clock
    random = SeededRandom(seed)
    configure()
}

/**
 * Returns the primitives of krypt over [testEnvironment].
 *
 * @param clock the clock; a [TestClock] at the epoch by default.
 * @param seed the seed of the randomness; 42 by default.
 * @param configure changes what else differs.
 * @return the primitives.
 * @since 1.0.0
 */
public fun testCrypto(
    clock: Clock = TestClock(),
    seed: Long = DEFAULT_SEED,
    configure: EnvironmentBuilder.() -> Unit = {},
): Crypto = Crypto(testEnvironment(clock = clock, seed = seed, configure = configure))
