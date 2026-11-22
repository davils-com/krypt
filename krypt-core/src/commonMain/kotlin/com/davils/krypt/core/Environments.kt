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

package com.davils.krypt.core

/**
 * Builds a validated environment that starts from [base] and changes what [configure] sets.
 *
 * @param base the environment every property starts from; [Environment.Default] by default.
 * @param configure sets what differs from [base], such as `policy = CryptoPolicy.Cnsa2` or `events(bus)`.
 * @return the environment.
 * @throws com.davils.kore.core.validation.report.ValidationException if the event capacity is below 1 or above its
 *   hard ceiling.
 * @since 1.0.0
 */
public fun environment(base: Environment = Environment.Default, configure: EnvironmentBuilder.() -> Unit): Environment {
    val builder = EnvironmentBuilder()
    builder.from(base)
    builder.configure()
    return builder.build()
}
