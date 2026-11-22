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

package com.davils.krypt.acme.internal

import com.davils.krypt.acme.AcmeError

internal class Links private constructor(private val text: String) {
    private var position: Int = 0

    private fun all(into: MutableList<Link>, maximum: Int) {
        skipSpace()
        while (position < text.length) {
            into += link()
            refuseUnless(condition = into.size <= maximum, error = AcmeError.LimitExceeded)
            skipSpace()
            refuseUnless(position == text.length || next() == COMMA)
            skipSpace()
        }
    }

    private fun link(): Link {
        refuseUnless(next() == OPEN)
        val end = text.indexOf(CLOSE, startIndex = position)
        refuseUnless(end >= 0)
        val target = text.substring(startIndex = position, endIndex = end)
        position = end + 1
        val relations = mutableListOf<String>()
        skipSpace()
        while (peek() == SEMICOLON) {
            position += 1
            skipSpace()
            val name = token()
            skipSpace()
            refuseUnless(next() == EQUALS)
            skipSpace()
            val value = parameterValue()
            val isRelation = name.equals(other = RELATION, ignoreCase = true)
            if (isRelation) relations += value.split(' ').filter { relation -> relation.isNotEmpty() }
            skipSpace()
        }
        return Link(target = target, relations = relations.map { relation -> relation.lowercase() })
    }

    private fun parameterValue(): String {
        if (peek() == QUOTE) return quoted()
        return token()
    }

    private fun quoted(): String {
        position += 1
        val value = StringBuilder()
        var char = next()
        while (char != QUOTE) {
            if (char == BACKSLASH) char = next()
            value.append(char)
            char = next()
        }
        return value.toString()
    }

    private fun token(): String {
        val start = position
        while (peek().isTokenChar()) position += 1
        refuseUnless(position > start)
        return text.substring(startIndex = start, endIndex = position)
    }

    private fun skipSpace() {
        while (peek() == ' ' || peek() == '\t') position += 1
    }

    private fun peek(): Char = text.getOrNull(position) ?: END

    private fun next(): Char {
        val char = peek()
        refuseUnless(char != END)
        position += 1
        return char
    }

    private fun Char.isTokenChar(): Boolean = this in '!'..'~' && this !in SEPARATORS

    companion object {
        private const val END: Char = '\u0000'
        private const val OPEN: Char = '<'
        private const val CLOSE: Char = '>'
        private const val COMMA: Char = ','
        private const val SEMICOLON: Char = ';'
        private const val EQUALS: Char = '='
        private const val QUOTE: Char = '"'
        private const val BACKSLASH: Char = '\\'
        private const val RELATION: String = "rel"
        private const val SEPARATORS: String = "()<>@,;:\\\"/[]?={}"

        fun parse(values: List<String>, maximum: Int): List<Link> {
            val links = mutableListOf<Link>()
            values.forEach { value -> Links(value).all(into = links, maximum = maximum) }
            return links
        }
    }
}
