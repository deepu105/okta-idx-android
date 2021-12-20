package com.okta.idx.android.browser

import android.os.Bundle
import android.view.View
import androidx.fragment.app.viewModels
import androidx.navigation.fragment.findNavController
import com.okta.idx.android.dashboard.TokenViewModel
import com.okta.idx.android.dynamic.databinding.FragmentBrowserBinding
import com.okta.idx.android.util.BaseFragment

internal class BrowserFragment : BaseFragment<FragmentBrowserBinding>(
    FragmentBrowserBinding::inflate
) {
    private val viewModel by viewModels<BrowserViewModel>()

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.loginWithBrowserButton.setOnClickListener {
            viewModel.login(requireContext())
        }

        viewModel.state.observe(viewLifecycleOwner) { state ->
            when (state) {
                is BrowserState.Error -> {
                    binding.errorTextView.text = state.message
                }
                BrowserState.Idle -> {

                }
                is BrowserState.Tokens -> {
                    TokenViewModel._tokens = state.tokens
                    findNavController().navigate(BrowserFragmentDirections.browserToDashboard())
                }
            }
        }
    }
}
