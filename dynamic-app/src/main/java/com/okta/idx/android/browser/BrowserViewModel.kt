package com.okta.idx.android.browser

import android.content.Context
import android.net.Uri
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.okta.idx.android.dynamic.BuildConfig
import com.okta.idx.android.dynamic.SocialRedirectCoordinator
import com.okta.oauth2.AuthorizationCodeFlow
import com.okta.oidc.browserredirect.BrowserRedirectClient
import com.okta.oidc.kotlin.client.OidcClient
import com.okta.oidc.kotlin.client.OidcClientResult
import com.okta.oidc.kotlin.client.OidcConfiguration
import com.okta.oidc.kotlin.dto.OidcTokens
import kotlinx.coroutines.launch
import okhttp3.HttpUrl.Companion.toHttpUrl
import timber.log.Timber

class BrowserViewModel : ViewModel() {
    private lateinit var client: BrowserRedirectClient
    private var authorizationCodeFlowContext: AuthorizationCodeFlow.Context? = null

    private val _state = MutableLiveData<BrowserState>(BrowserState.Idle)
    val state: LiveData<BrowserState> = _state

    init {
        SocialRedirectCoordinator.listener = ::handleRedirect

        viewModelScope.launch {
            val oidcConfiguration = OidcConfiguration(
                clientId = BuildConfig.CLIENT_ID,
                scopes = setOf("openid", "email", "profile", "offline_access"),
            )
            when (val clientResult = OidcClient.create(
                oidcConfiguration,
                "${BuildConfig.ISSUER}/.well-known/openid-configuration".toHttpUrl(),
            )) {
                is OidcClientResult.Error -> {
                    Timber.e(clientResult.exception, "Failed to create client")
                }
                is OidcClientResult.Success -> {
                    val configuration = AuthorizationCodeFlow.Configuration(
                        redirectUri = BuildConfig.REDIRECT_URI,
                        endSessionRedirectUri = BuildConfig.END_SESSION_REDIRECT_URI,
                    )
                    val oidcClient = clientResult.result
                    val authorizationCodeFlow = AuthorizationCodeFlow(configuration, oidcClient)
                    client = BrowserRedirectClient(authorizationCodeFlow)
                }
            }
        }
    }

    override fun onCleared() {
        SocialRedirectCoordinator.listener = null
    }

    fun login(context: Context) {
        authorizationCodeFlowContext = client.login(context)
    }

    fun handleRedirect(uri: Uri) {
        viewModelScope.launch {
            when (val result = client.resume(uri, authorizationCodeFlowContext!!)) {
                is AuthorizationCodeFlow.Result.Error -> {
                    _state.value = BrowserState.Error(result.message)
                }
                AuthorizationCodeFlow.Result.MissingResultCode -> {
                    _state.value = BrowserState.Error("Invalid redirect. Missing result code.")
                }
                AuthorizationCodeFlow.Result.RedirectSchemeMismatch -> {
                    _state.value = BrowserState.Error("Invalid redirect. Redirect scheme mismatch.")
                }
                is AuthorizationCodeFlow.Result.Tokens -> {
                    _state.value = BrowserState.Tokens(result.tokens)
                }
            }
        }
    }
}

sealed class BrowserState {
    object Idle : BrowserState()
    data class Error(val message: String): BrowserState()
    data class Tokens(val tokens: OidcTokens): BrowserState()
}
