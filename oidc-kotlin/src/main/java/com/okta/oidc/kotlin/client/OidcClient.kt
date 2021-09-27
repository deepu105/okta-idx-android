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
package com.okta.oidc.kotlin.client

import com.okta.oidc.kotlin.dto.OidcIntrospectInfo
import com.okta.oidc.kotlin.dto.OidcTokens
import com.okta.oidc.kotlin.dto.OidcUserInfo
import com.okta.oidc.kotlin.util.performRequest
import com.okta.oidc.kotlin.util.performRequestNonJson
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import okhttp3.FormBody
import okhttp3.HttpUrl
import okhttp3.Request

// TODO: Document
class OidcClient internal constructor(
    private val configuration: OidcConfiguration,
    private val tokenEndpoints: OidcTokenEndpoints,
) {
    companion object {
        suspend fun create(
            configuration: OidcConfiguration,
            discoveryUrl: HttpUrl
        ): OidcClientResult<OidcClient> {
            val request = Request.Builder()
                .url(discoveryUrl)
                .build()
            val dtoResult =
                configuration.performRequest<OidcTokenEndpoints>(request)
            return when (dtoResult) {
                is OidcClientResult.Error -> {
                    OidcClientResult.Error(dtoResult.exception)
                }
                is OidcClientResult.Response -> {
                    OidcClientResult.Response(OidcClient(configuration, dtoResult.response))
                }
            }
        }
    }

    suspend fun getUserInfo(): OidcClientResult<OidcUserInfo> {
        val accessToken = withContext(configuration.storageDispatcher) {
            configuration.storage.get("access_token")
        } ?: return OidcClientResult.Error(IllegalStateException("No access token."))

        val request = Request.Builder()
            .addHeader("authorization", "Bearer $accessToken")
            .url(tokenEndpoints.userInfoEndpoint)
            .build()

        return configuration.performRequest<JsonObject, OidcUserInfo>(request) {
            OidcUserInfo(it)
        }
    }

    suspend fun refreshToken(): OidcClientResult<OidcTokens> {
        val refreshToken = withContext(configuration.storageDispatcher) {
            configuration.storage.get("refresh_token")
        } ?: return OidcClientResult.Error(IllegalStateException("No refresh token."))

        val formBody = FormBody.Builder()
            .add("client_id", configuration.clientId)
            .add("grant_type", "refresh_token")
            .add("refresh_token", refreshToken)
            .add("scope", configuration.scopes.joinToString(separator = " "))
            .build()

        val request = Request.Builder()
            .url(tokenEndpoints.tokenEndpoint)
            .post(formBody)
            .build()

        val result = configuration.performRequest<OidcTokens>(request)
        (result as? OidcClientResult.Response<OidcTokens>)?.let {
            configuration.storeTokens(it.response)
        }
        return result
    }

    suspend fun revokeToken(token: String): OidcClientResult<Unit> {
        val formBody = FormBody.Builder()
            .add("client_id", configuration.clientId)
            .add("token", token)
            .build()

        val request = Request.Builder()
            .url(tokenEndpoints.revocationEndpoint)
            .post(formBody)
            .build()

        // TODO: Remove token?
        return configuration.performRequestNonJson(request)
    }

    suspend fun introspectToken(
        token: String,
        tokenType: String
    ): OidcClientResult<OidcIntrospectInfo> {
        val formBody = FormBody.Builder()
            .add("client_id", configuration.clientId)
            .add("token", token)
            .add("token_type_hint", tokenType)
            .build()

        val request = Request.Builder()
            .url(tokenEndpoints.introspectionEndpoint)
            .post(formBody)
            .build()

        return configuration.performRequest<JsonObject, OidcIntrospectInfo>(request) {
            OidcIntrospectInfo(it)
        }
    }

    private suspend fun OidcConfiguration.storeTokens(tokens: OidcTokens) {
        val storage = configuration.storage
        withContext(storageDispatcher) {
            tokens.refreshToken?.let { storage.save("refresh_token", it) }
            tokens.idToken?.let { storage.save("id_token", it) }
            tokens.accessToken.let { storage.save("access_token", it) }
        }
    }
}
