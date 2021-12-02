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
package com.okta.idx.android.dashboard

import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.okta.idx.android.dynamic.BuildConfig
import com.okta.oidc.kotlin.client.OidcClient
import com.okta.oidc.kotlin.client.OidcClientResult
import com.okta.oidc.kotlin.client.OidcConfiguration
import com.okta.oidc.kotlin.dto.OidcTokenType
import com.okta.oidc.kotlin.dto.OidcTokens
import kotlinx.coroutines.launch
import okhttp3.HttpUrl.Companion.toHttpUrl
import timber.log.Timber

internal class DashboardViewModel : ViewModel() {
    private val _logoutStateLiveData = MutableLiveData<LogoutState>(LogoutState.Idle)
    val logoutStateLiveData: LiveData<LogoutState> = _logoutStateLiveData

    private val _userInfoLiveData = MutableLiveData<Map<String, String>>(emptyMap())
    val userInfoLiveData: LiveData<Map<String, String>> = _userInfoLiveData

    private var oidcClient: OidcClient? = null

    init {
        viewModelScope.launch {
            val configuration = OidcConfiguration(BuildConfig.CLIENT_ID, setOf("openid", "email", "profile", "offline_access"))
            when (val clientResult = OidcClient.create(configuration, "${BuildConfig.ISSUER}/.well-known/openid-configuration".toHttpUrl())) {
                is OidcClientResult.Error -> {
                    Timber.e(clientResult.exception, "Failed to create client")
                }
                is OidcClientResult.Success -> {
                    oidcClient = clientResult.result
                    oidcClient?.storeTokens(OidcTokens(
                        tokenType =  TokenViewModel.tokenResponse.tokenType,
                        expiresIn = TokenViewModel.tokenResponse.expiresIn,
                        accessToken = TokenViewModel.tokenResponse.accessToken,
                        scope = TokenViewModel.tokenResponse.scope,
                        refreshToken = TokenViewModel.tokenResponse.refreshToken,
                        idToken = TokenViewModel.tokenResponse.idToken,
                    ))
                    getUserInfo()
                }
            }
        }
    }

    fun logout() {
        val client = oidcClient
        if (client == null) {
            Timber.d("Client not present.")
            return
        }
        _logoutStateLiveData.value = LogoutState.Loading

        viewModelScope.launch {
            when (client.revokeToken(OidcTokenType.REFRESH_TOKEN)) {
                is OidcClientResult.Error -> {
                    _logoutStateLiveData.postValue(LogoutState.Failed)
                }
                is OidcClientResult.Success -> {
                    _logoutStateLiveData.postValue(LogoutState.Success)
                }
            }
        }
    }

    private suspend fun getUserInfo() {
        when (val userInfoResult = oidcClient?.getUserInfo()) {
            is OidcClientResult.Error -> {
                Timber.e(userInfoResult.exception, "Failed to fetch user info.")
                _userInfoLiveData.postValue(emptyMap())
            }
            is OidcClientResult.Success -> {
                _userInfoLiveData.postValue(userInfoResult.result.asMap())
            }
        }
    }

    fun acknowledgeLogoutSuccess() {
        _logoutStateLiveData.value = LogoutState.Idle
    }

    sealed class LogoutState {
        object Idle : LogoutState()
        object Loading : LogoutState()
        object Success : LogoutState()
        object Failed : LogoutState()
    }
}
