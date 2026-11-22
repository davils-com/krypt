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

package com.davils.krypt.acme

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import java.lang.reflect.Constructor
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier

private const val INTERNAL_PACKAGE: String = "com.davils.krypt.acme.internal"

private fun publicConstructorsOf(type: Class<*>): List<Constructor<*>> =
    type.declaredConstructors.filter { constructor -> Modifier.isPublic(constructor.modifiers) }

private fun isGuarded(constructor: Constructor<*>): Boolean =
    constructor.parameterTypes.any { parameter -> parameter.packageName == INTERNAL_PACKAGE }

class JavaReachabilityTest : FunSpec({
    test("a session cannot be built around an account URL that was not checked") {
        val constructors = publicConstructorsOf(AcmeSession::class.java)
        constructors.shouldNotBeEmpty()
        constructors.all { constructor -> isGuarded(constructor) } shouldBe true
    }

    test("the session constructor refuses a missing value") {
        val constructor = publicConstructorsOf(AcmeSession::class.java).single()
        shouldThrow<InvocationTargetException> { constructor.newInstance(null) }
    }
})
