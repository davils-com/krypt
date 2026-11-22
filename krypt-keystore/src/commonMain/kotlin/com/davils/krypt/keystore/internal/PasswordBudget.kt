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

package com.davils.krypt.keystore.internal

import com.davils.krypt.keystore.KeystoreFailure

internal class PasswordBudget(private val iterations: Int) {
    private var spent: Long = 0L

    fun spend(count: Int) {
        val total = spent + count
        KeystoreRefusal.ensure(total <= iterations, KeystoreFailure.Refused)
        spent = total
    }
}
