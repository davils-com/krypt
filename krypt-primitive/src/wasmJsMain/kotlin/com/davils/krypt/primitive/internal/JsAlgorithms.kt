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

@file:OptIn(ExperimentalWasmJsInterop::class)

package com.davils.krypt.primitive.internal

@JsFun("(name) => ({ name: name })")
internal external fun named(name: String): JsAny

@JsFun("(name, hash) => ({ name: name, hash: hash })")
internal external fun withHash(name: String, hash: String): JsAny

@JsFun("(name, curve) => ({ name: name, namedCurve: curve })")
internal external fun withCurve(name: String, curve: String): JsAny

@JsFun("(name, iv) => ({ name: name, iv: iv })")
internal external fun withIv(name: String, iv: JsAny): JsAny

@JsFun("(name, iv, aad) => ({ name: name, iv: iv, additionalData: aad, tagLength: 128 })")
internal external fun aeadParameters(name: String, iv: JsAny, aad: JsAny): JsAny

@JsFun("(saltLength) => ({ name: 'RSA-PSS', saltLength: saltLength })")
internal external fun pssParameters(saltLength: Int): JsAny

@JsFun("(hash) => ({ name: 'ECDSA', hash: hash })")
internal external fun ecdsaParameters(hash: String): JsAny

@JsFun("(salt, iterations, hash) => ({ name: 'PBKDF2', salt: salt, iterations: iterations, hash: hash })")
internal external fun pbkdf2Parameters(salt: JsAny, iterations: Int, hash: String): JsAny

@JsFun("(name, publicKey) => ({ name: name, public: publicKey })")
internal external fun agreementParameters(name: String, publicKey: JsAny): JsAny

@JsFun("(hash, bits) => ({ name: 'HMAC', hash: hash, length: bits })")
internal external fun hmacImport(hash: String, bits: Int): JsAny

@JsFun("(name, bits, hash) => ({ name, modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash })")
internal external fun rsaGeneration(name: String, bits: Int, hash: String): JsAny
