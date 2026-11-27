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

package com.davils.krypt.core.telemetry

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.Environment
import com.davils.kontinuity.core.Environment as ResilienceEnvironment
import com.davils.kontinuity.core.environment as resilienceEnvironment

/**
 * Returns the environment of kontinuity that reports to the same tracer, meters and event bus as this environment, so
 * the retries and caches a krypt module runs report next to its own events. Shared between the modules of krypt.
 *
 * @receiver the environment of krypt.
 * @return the environment of kontinuity.
 * @since 1.2.0
 */
@DavilsInternal
public fun Environment.resilience(): ResilienceEnvironment {
    val source = this
    return resilienceEnvironment {
        tracer = source.tracer
        source.meters?.let { registry -> meters(registry) }
        source.events?.let { bus -> events(bus) }
    }
}
