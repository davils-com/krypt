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

import com.davils.konfetti.core.Event

/**
 * An event of krypt, such as a rotated key, a reloaded TLS identity or an issued certificate, which a component
 * publishes on its own `Flow` and, when the environment names an event bus, on its konfetti topic.
 *
 * Events name keys and certificates by their ids and fingerprints, never by their material.
 *
 * @since 1.0.0
 */
public interface CryptoEvent : Event {
    /**
     * The component that published the event, such as `keyset` or `tls`.
     *
     * @since 1.0.0
     */
    public val component: String
}
