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

package com.davils.krypt.cms.enveloped

/**
 * The kinds of RecipientInfo of RFC 5652 and RFC 9629.
 *
 * @since 1.0.0
 */
public enum class RecipientType {
    /**
     * KeyTransRecipientInfo.
     *
     * @since 1.0.0
     */
    KeyTransport,

    /**
     * KeyAgreeRecipientInfo.
     *
     * @since 1.0.0
     */
    KeyAgreement,

    /**
     * KEKRecipientInfo.
     *
     * @since 1.0.0
     */
    Kek,

    /**
     * PasswordRecipientInfo.
     *
     * @since 1.0.0
     */
    Password,

    /**
     * KEMRecipientInfo within an OtherRecipientInfo.
     *
     * @since 1.0.0
     */
    Kem,

    /**
     * An OtherRecipientInfo of a type krypt does not know.
     *
     * @since 1.0.0
     */
    Other,
}
