%%% @doc Main test suite for SSL certificate management system.
%%%
%%% This module provides a centralized test runner for all SSL certificate
%%% management tests including unit tests, integration tests, and
%%% performance tests.

-module(ssl_cert_test_suite).

-include_lib("eunit/include/eunit.hrl").
-include("../include/events.hrl").

%% Test runner exports
-export([
    run_all_tests/0,
    run_unit_tests/0,
    run_integration_tests/0,
    run_performance_tests/0,
    print_test_coverage/0,
    setup_test_environment/0,
    cleanup_test_environment/0
]).

%%%--------------------------------------------------------------------
%%% Test Suite Runner
%%%--------------------------------------------------------------------

-doc """
Runs all SSL certificate management tests.

This function executes all test modules in the correct order,
providing comprehensive coverage of the SSL certificate system.
""".
all_test_() ->
    % 60 second timeout for complete test suite
    {timeout, 60, [
        {"SSL Utils Tests", ssl_utils_tests:ssl_utils_test_()},
        {"SSL Cert Validation Tests", ssl_cert_validation_tests:ssl_cert_validation_test_()},
        {"SSL Cert State Tests", ssl_cert_state_tests:ssl_cert_state_test_()},
        {"SSL Cert Challenge Tests", ssl_cert_challenge_tests:ssl_cert_challenge_test_()},
        {"SSL Cert Ops Tests", ssl_cert_ops_tests:ssl_cert_ops_test_()},
        {"ACME URL Tests", acme_url_tests:acme_url_test_()},
        {"ACME Crypto Tests", acme_crypto_tests:acme_crypto_test_()},
        {"ACME CSR Tests", acme_csr_tests:acme_csr_test_()},
        {"ACME HTTP Tests", acme_http_tests:acme_http_test_()},
        {"ACME Protocol Tests", acme_protocol_tests:acme_protocol_test_()},
        {"Integration Tests", ssl_cert_integration_tests:ssl_cert_integration_test_()}
    ]}.

%%%--------------------------------------------------------------------
%%% Test Categories
%%%--------------------------------------------------------------------

-doc """
Runs only unit tests (fast tests without external dependencies).
""".
unit_tests_test_() ->
    {timeout, 30, [
        {"SSL Utils Unit Tests", ssl_utils_tests:ssl_utils_test_()},
        {"SSL Cert Validation Unit Tests", ssl_cert_validation_tests:ssl_cert_validation_test_()},
        {"ACME URL Unit Tests", acme_url_tests:acme_url_test_()},
        {"ACME Crypto Unit Tests", acme_crypto_tests:acme_crypto_test_()}
    ]}.

-doc """
Runs only integration tests (tests that verify module interactions).
""".
integration_tests_test_() ->
    {timeout, 45, [
        {"SSL Cert Integration Tests", ssl_cert_integration_tests:ssl_cert_integration_test_()},
        {"SSL Cert State Integration", ssl_cert_state_tests:ssl_cert_state_test_()},
        {"SSL Cert Challenge Integration", ssl_cert_challenge_tests:ssl_cert_challenge_test_()}
    ]}.

-doc """
Runs only performance tests.
""".
performance_tests_test_() ->
    {timeout, 30, [
        {"Crypto Performance", acme_crypto_tests:acme_crypto_test_()},
        {"Ops Performance", ssl_cert_ops_tests:ssl_cert_ops_test_()}
    ]}.

%%%--------------------------------------------------------------------
%%% Test Utilities
%%%--------------------------------------------------------------------

-doc """
Prints test coverage summary.
""".
print_test_coverage() ->
    TestModules = [
        ssl_utils_tests,
        ssl_cert_validation_tests,
        ssl_cert_state_tests,
        ssl_cert_challenge_tests,
        ssl_cert_ops_tests,
        acme_url_tests,
        acme_crypto_tests,
        acme_csr_tests,
        acme_http_tests,
        acme_protocol_tests,
        ssl_cert_integration_tests
    ],

    ?event(test_suite, test_coverage_start),
    ?event(test_suite, {test_modules_count, length(TestModules)}),
    lists:foreach(
        fun(Module) ->
            ModuleFunctions = erlang:apply(Module, module_info, [exports]),
            TestFunctions = [
                F
             || {F, A} <- ModuleFunctions,
                string:find(atom_to_list(F), "_test") =/= nomatch,
                A =:= 0
            ],
            ?event(test_suite, {module_test_count, Module, length(TestFunctions)})
        end,
        TestModules
    ),
    ?event(test_suite, test_coverage_end).

%%%--------------------------------------------------------------------
%%% Test Configuration
%%%--------------------------------------------------------------------

-doc """
Sets up test environment.
""".
setup_test_environment() ->
    % Set up any global test configuration
    application:ensure_all_started(crypto),
    application:ensure_all_started(public_key),
    ok.

-doc """
Cleans up test environment.
""".
cleanup_test_environment() ->
    % Clean up any test artifacts
    ok.

%%%--------------------------------------------------------------------
%%% Main Test Entry Points
%%%--------------------------------------------------------------------

% These can be called from the command line:
% rebar3 eunit --module=ssl_cert_test_suite --function=run_all_tests
% rebar3 eunit --module=ssl_cert_test_suite --function=run_unit_tests
% rebar3 eunit --module=ssl_cert_test_suite --function=run_integration_tests

run_all_tests() ->
    setup_test_environment(),
    print_test_coverage(),
    Result = eunit:test({module, ssl_cert_test_suite}, [verbose]),
    cleanup_test_environment(),
    Result.

run_unit_tests() ->
    setup_test_environment(),
    Result = eunit:test(fun unit_tests_test_/0, [verbose]),
    cleanup_test_environment(),
    Result.

run_integration_tests() ->
    setup_test_environment(),
    Result = eunit:test(fun integration_tests_test_/0, [verbose]),
    cleanup_test_environment(),
    Result.

run_performance_tests() ->
    setup_test_environment(),
    Result = eunit:test(fun performance_tests_test_/0, [verbose]),
    cleanup_test_environment(),
    Result.
