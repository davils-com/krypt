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

import kotlinx.io.bytestring.ByteString

/**
 * Comparisons whose running time depends on the length of their input alone, never on where two values differ.
 *
 * Every comparison of a MAC, a tag, a digest of a secret or a password hash in krypt goes through here, so an attacker
 * who measures the time of a refusal learns nothing about how much of a guess was right. The length of the values is
 * not secret: values of different length are unequal, after a pass over the shorter one.
 *
 * @since 1.0.0
 */
public object ConstantTime {
    /**
     * Compares [first] and [second] in constant time.
     *
     * @param first the first value.
     * @param second the second value.
     * @return true if both have the same length and the same bytes.
     * @since 1.0.0
     */
    public fun equals(first: ByteArray, second: ByteArray): Boolean {
        var difference = first.size xor second.size
        val shared = minOf(a = first.size, b = second.size)
        for (index in 0 until shared) difference = difference or (first[index].toInt() xor second[index].toInt())
        return difference == 0
    }

    /**
     * Compares [first] and [second] in constant time.
     *
     * @param first the first value.
     * @param second the second value.
     * @return true if both have the same length and the same bytes.
     * @since 1.0.0
     */
    public fun equals(first: ByteString, second: ByteString): Boolean {
        var difference = first.size xor second.size
        val shared = minOf(a = first.size, b = second.size)
        for (index in 0 until shared) difference = difference or (first[index].toInt() xor second[index].toInt())
        return difference == 0
    }

    /**
     * Picks [whenTrue] or [whenFalse] without a branch on [condition].
     *
     * @param condition the choice, which may be secret.
     * @param whenTrue the value for true.
     * @param whenFalse the value for false.
     * @return the chosen value.
     * @since 1.0.0
     */
    public fun select(condition: Boolean, whenTrue: Int, whenFalse: Int): Int {
        val mask = -condition.compareTo(false)
        return (whenTrue and mask) or (whenFalse and mask.inv())
    }
}
