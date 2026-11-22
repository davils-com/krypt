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

/**
 * Builds a [CtPolicy], starting from the policy of Chrome.
 *
 * @param configure changes what differs.
 * @return the policy.
 * @throws com.davils.kore.core.validation.report.ValidationException if a bound is out of range.
 * @since 1.0.0
 */
public fun ctPolicy(configure: CtPolicyBuilder.() -> Unit): CtPolicy {
    val builder = CtPolicyBuilder()
    builder.configure()
    return builder.build()
}
