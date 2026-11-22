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

package com.davils.krypt.asn1

/**
 * Thrown by a [DerReader] when the bytes are not what the structure expects; [Der.decode] turns it into a failed
 * outcome.
 *
 * The message names the failure and what was read, never the bytes, which may be secret.
 *
 * @property failure why the bytes were refused.
 * @param detail what the reader expected, such as `an INTEGER`.
 * @since 1.0.0
 */
public class DerException(public val failure: DerFailure, detail: String) :
    IllegalArgumentException("The DER input was refused ($failure): $detail")
