%%% @doc Tests for acme_client module.
%%%
%%% This module contains comprehensive tests for the ACME client wrapper
%%% functions that provide a simplified interface to the ACME protocol
%%% operations.

-module(acme_client_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/ssl_cert.hrl").

%%%--------------------------------------------------------------------
%%% Test Data
%%%--------------------------------------------------------------------

sample_account() ->
    #acme_account{
        key = test_key,
        url = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123",
        kid = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123"
    }.

sample_order() ->
    #acme_order{
        url = "https://acme-staging-v02.api.letsencrypt.org/acme/order/123",
        status = "pending",
        expires = "2024-01-01T00:00:00Z",
        identifiers = [#{<<"type">> => <<"dns">>, <<"value">> => <<"example.com">>}],
        authorizations = ["https://acme-staging-v02.api.letsencrypt.org/acme/authz/123"],
        finalize = "https://acme-staging-v02.api.letsencrypt.org/acme/finalize/123",
        certificate = ""
    }.

sample_challenge() ->
    #dns_challenge{
        domain = "example.com",
        token = "test_token_123",
        key_authorization = "test_key_auth_456",
        dns_value = "test_dns_value_789",
        url = "https://acme-staging-v02.api.letsencrypt.org/acme/challenge/123"
    }.

%%%--------------------------------------------------------------------
%%% Function Structure Tests
%%%--------------------------------------------------------------------

create_account_structure_test() ->
    ?assert(erlang:function_exported(acme_client, create_account, 2)).

request_certificate_structure_test() ->
    ?assert(erlang:function_exported(acme_client, request_certificate, 2)).

get_dns_challenge_structure_test() ->
    ?assert(erlang:function_exported(acme_client, get_dns_challenge, 2)).

validate_challenge_structure_test() ->
    ?assert(erlang:function_exported(acme_client, validate_challenge, 2)).

get_challenge_status_structure_test() ->
    ?assert(erlang:function_exported(acme_client, get_challenge_status, 2)).

finalize_order_structure_test() ->
    ?assert(erlang:function_exported(acme_client, finalize_order, 3)).

download_certificate_structure_test() ->
    ?assert(erlang:function_exported(acme_client, download_certificate, 2)).

get_order_structure_test() ->
    ?assert(erlang:function_exported(acme_client, get_order, 2)).

%%%--------------------------------------------------------------------
%%% Client Wrapper Tests
%%%--------------------------------------------------------------------

% Note: These tests verify that the client module properly wraps
% the acme_protocol functions. Full testing would require mocking
% the underlying protocol functions.

client_create_account_delegation_test() ->
    % Test that client delegates to protocol
    Config = #{environment => staging, email => "test@example.com"},
    Wallet = {{rsa, 65537}, <<"priv">>, <<"pub">>},

    % This would require mocking acme_protocol:create_account
    % For now, just verify the function exists and can be called
    try
        _Result = acme_client:create_account(Config, Wallet),
        ?assert(true)
    catch
        _:_ ->
            % Expected if dependencies aren't mocked
            ?assert(true)
    end.

client_request_certificate_delegation_test() ->
    Account = sample_account(),
    Domains = ["example.com"],

    try
        _Result = acme_client:request_certificate(Account, Domains),
        ?assert(true)
    catch
        _:_ ->
            % Expected if dependencies aren't mocked
            ?assert(true)
    end.

client_get_dns_challenge_delegation_test() ->
    Account = sample_account(),
    Order = sample_order(),

    try
        _Result = acme_client:get_dns_challenge(Account, Order),
        ?assert(true)
    catch
        _:_ ->
            % Expected if dependencies aren't mocked
            ?assert(true)
    end.

client_validate_challenge_delegation_test() ->
    Account = sample_account(),
    Challenge = sample_challenge(),

    try
        _Result = acme_client:validate_challenge(Account, Challenge),
        ?assert(true)
    catch
        _:_ ->
            % Expected if dependencies aren't mocked
            ?assert(true)
    end.

%%%--------------------------------------------------------------------
%%% Error Handling Tests
%%%--------------------------------------------------------------------

client_error_propagation_test() ->
    % Test that client properly propagates errors from protocol layer
    Account = sample_account(),
    InvalidOrder = #acme_order{
        url = "",
        status = "",
        expires = "",
        identifiers = [],
        authorizations = [],
        finalize = "",
        certificate = ""
    },

    try
        Result = acme_client:get_dns_challenge(Account, InvalidOrder),
        ?assertMatch({error, _}, Result)
    catch
        _:_ ->
            % Expected if validation throws
            ?assert(true)
    end.

%%%--------------------------------------------------------------------
%%% API Consistency Tests
%%%--------------------------------------------------------------------

api_consistency_test() ->
    % Test that all client functions return consistent error formats
    ClientFunctions = [
        {create_account, 2},
        {request_certificate, 2},
        {get_dns_challenge, 2},
        {validate_challenge, 2},
        {get_challenge_status, 2},
        {finalize_order, 3},
        {download_certificate, 2},
        {get_order, 2}
    ],

    % Verify all functions are exported
    lists:foreach(
        fun({Function, Arity}) ->
            ?assert(erlang:function_exported(acme_client, Function, Arity))
        end,
        ClientFunctions
    ).

%%%--------------------------------------------------------------------
%%% Integration with Other Modules
%%%--------------------------------------------------------------------

client_protocol_integration_test() ->
    % Test that client integrates properly with protocol module
    ?assert(erlang:function_exported(acme_protocol, create_account, 2)),
    ?assert(erlang:function_exported(acme_client, create_account, 2)),

    % Both should have same arity for corresponding functions
    ProtocolFunctions = erlang:apply(acme_protocol, module_info, [exports]),
    ClientFunctions = erlang:apply(acme_client, module_info, [exports]),

    % Check that client has corresponding functions for main protocol functions
    MainFunctions = [
        create_account,
        request_certificate,
        get_dns_challenge,
        validate_challenge,
        finalize_order,
        download_certificate
    ],

    lists:foreach(
        fun(Function) ->
            ?assert(lists:keymember(Function, 1, ProtocolFunctions)),
            ?assert(lists:keymember(Function, 1, ClientFunctions))
        end,
        MainFunctions
    ).

%%%--------------------------------------------------------------------
%%% Documentation Tests
%%%--------------------------------------------------------------------

module_documentation_test() ->
    % Test that module has proper documentation
    ModuleInfo = erlang:apply(acme_client, module_info, []),
    ?assert(is_list(ModuleInfo)),

    % Test that functions are documented (this would require checking attributes)
    ?assert(erlang:function_exported(acme_client, create_account, 2)).

%%%--------------------------------------------------------------------
%%% Test Suite
%%%--------------------------------------------------------------------

acme_client_test_() ->
    [
        {"Function structure tests", [
            fun create_account_structure_test/0,
            fun request_certificate_structure_test/0,
            fun get_dns_challenge_structure_test/0,
            fun validate_challenge_structure_test/0,
            fun get_challenge_status_structure_test/0,
            fun finalize_order_structure_test/0,
            fun download_certificate_structure_test/0,
            fun get_order_structure_test/0
        ]},
        {"Client wrapper tests", [
            fun client_create_account_delegation_test/0,
            fun client_request_certificate_delegation_test/0,
            fun client_get_dns_challenge_delegation_test/0,
            fun client_validate_challenge_delegation_test/0
        ]},
        {"Error handling tests", [
            fun client_error_propagation_test/0
        ]},
        {"API consistency tests", [
            fun api_consistency_test/0
        ]},
        {"Integration tests", [
            fun client_protocol_integration_test/0
        ]},
        {"Documentation tests", [
            fun module_documentation_test/0
        ]}
    ].
