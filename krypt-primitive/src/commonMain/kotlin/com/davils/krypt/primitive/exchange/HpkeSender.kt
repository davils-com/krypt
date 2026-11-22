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

package com.davils.krypt.primitive.exchange

import kotlinx.io.bytestring.ByteString

/**
 * The result of setting up a sender: the encapsulated key the recipient needs and the context that seals.
 *
 * @property encapsulated the encapsulated key, sent to the recipient once.
 * @property context the context of the sender.
 * @since 1.0.0
 */
public class HpkeSender(public val encapsulated: ByteString, public val context: HpkeContext) {
    /**
     * Shows the size of the encapsulated key and the context.
     *
     * @return the sender as text.
     * @since 1.0.0
     */
    override fun toString(): String = "HpkeSender(encapsulated=${encapsulated.size}, $context)"
}
