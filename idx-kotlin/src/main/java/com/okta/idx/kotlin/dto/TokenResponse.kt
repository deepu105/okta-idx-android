/*
 * Copyright 2021-Present Okta, Inc.
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
package com.okta.idx.kotlin.dto

/**
 * Tokens created as a result of exchanging a successful response.
 */
class TokenResponse internal constructor(
    /** The access token. */
    val accessToken: String,

    /** The time interval after which this token will expire. */
    val expiresIn: String,

    /** The id token. */
    val idToken: String,

    /** The refresh token, if available. */
    val refreshToken: String?,

    /** The access scopes for this token. */
    val scope: String,

    /** The type of this token. */
    val tokenType: String,
)
