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

package com.davils.krypt.primitive

/**
 * Thrown when the crypto policy of the environment forbids an operation, such as signing with RSA PKCS #1 v1.5 under
 * the modern profile or generating a P-256 key under CNSA 2.0.
 *
 * @param detail what the policy forbids.
 * @since 1.0.0
 */
public class PolicyViolationException(detail: String) : CryptoException("The crypto policy forbids $detail")
