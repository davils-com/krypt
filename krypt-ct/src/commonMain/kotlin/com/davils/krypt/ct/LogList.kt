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

package com.davils.krypt.ct

import kotlinx.io.bytestring.ByteString

private const val MAXIMUM_LOGS: Int = 1_024

/**
 * The logs the application trusts, such as those of the log list of a browser vendor.
 *
 * @param logs the logs, each id once.
 * @constructor Holds [logs].
 * @throws IllegalArgumentException if there are more than 1024 logs or an id repeats.
 * @since 1.0.0
 */
public class LogList(logs: List<CtLog>) {
    /**
     * The logs.
     *
     * @since 1.0.0
     */
    public val logs: List<CtLog> = logs.toList()

    init {
        require(this.logs.size <= MAXIMUM_LOGS) { "A log list holds at most $MAXIMUM_LOGS logs" }
        require(this.logs.toSet().size == this.logs.size) { "A log appears once in a log list" }
    }

    /**
     * Returns the log with [logId].
     *
     * @param logId the id.
     * @return the log, or null.
     * @since 1.0.0
     */
    public fun find(logId: ByteString): CtLog? = logs.firstOrNull { log -> log.logId == logId }

    /**
     * Compares the logs.
     *
     * @param other the other object.
     * @return true if [other] holds the same logs.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is LogList && logs == other.logs

    /**
     * Hashes the logs.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = logs.hashCode()

    /**
     * Shows the number of logs.
     *
     * @return the list as text.
     * @since 1.0.0
     */
    override fun toString(): String = "LogList(${logs.size} logs)"
}
