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

package com.davils.krypt.testing.acme

import com.davils.krypt.acme.AcmeIdentifier

internal data class FakeOrder(
    val id: Int,
    val accountId: Int,
    val identifiers: List<AcmeIdentifier>,
    val authorizationIds: List<Int>,
    val status: String,
    val certificateId: Int? = null,
    val replaces: String? = null,
    val polls: Int = 0,
    val notBefore: String? = null,
    val notAfter: String? = null,
)
