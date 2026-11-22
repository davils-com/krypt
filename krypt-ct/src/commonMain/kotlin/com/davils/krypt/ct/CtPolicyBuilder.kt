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

package com.davils.krypt.ct

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.kore.core.dsl.ValidatingBuilder

private const val SHORT_DAYS: Int = 180
private const val SHORT_COUNT: Int = 2
private const val LONG_COUNT: Int = 3
private const val OPERATORS: Int = 2

/**
 * Builds a [CtPolicy], starting from the policy of Chrome.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class CtPolicyBuilder internal constructor() : ValidatingBuilder<CtPolicy>() {
    override val subject: String get() = "ctPolicy"

    /**
     * See [CtPolicy.shortLifetimeDays].
     *
     * @since 1.0.0
     */
    public var shortLifetimeDays: Int = SHORT_DAYS
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CtPolicy.minimumForShort].
     *
     * @since 1.0.0
     */
    public var minimumForShort: Int = SHORT_COUNT
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CtPolicy.minimumForLong].
     *
     * @since 1.0.0
     */
    public var minimumForLong: Int = LONG_COUNT
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [CtPolicy.minimumOperators].
     *
     * @since 1.0.0
     */
    public var minimumOperators: Int = OPERATORS
        set(value) {
            checkOpen()
            field = value
        }

    override fun assemble(): CtPolicy = CtPolicy(this)
}
