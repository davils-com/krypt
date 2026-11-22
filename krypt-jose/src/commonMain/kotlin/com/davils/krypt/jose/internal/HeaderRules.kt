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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.jose.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.collection.OrderedSet
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JsonValue

internal object HeaderRules {
    fun checkTypes(header: JsonValue.Object) {
        HeaderNames.TEXTS.forEach { name -> header.text(name) }
        header.bool(HeaderNames.BASE64)
        header.integer(HeaderNames.COUNT)
        header.member(HeaderNames.EPHEMERAL_KEY)
        header.member(HeaderNames.KEY)
        val critical = header.strings(HeaderNames.CRITICAL)
        require(critical == null || critical.isNotEmpty())
        val chain = header.strings(HeaderNames.CHAIN)
        require(chain == null || chain.isNotEmpty())
    }

    fun criticalFailure(protected: JsonValue.Object, header: JsonValue.Object, understood: Set<String>): JoseFailure? {
        val critical = header.stringsOf(HeaderNames.CRITICAL) ?: return null
        val isProtected = HeaderNames.CRITICAL in protected
        val isDistinct = OrderedSet(critical).size == critical.size
        val isKnown = critical.all { name -> name !in HeaderNames.REGISTERED && name in header && name in understood }
        return JoseFailure.UnknownCritical.takeUnless { isProtected && isDistinct && isKnown }
    }
}
