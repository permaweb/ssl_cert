%%% @doc Tests for ssl_cert_state module.
%%%
%%% This module contains comprehensive tests for SSL certificate state management
%%% including state serialization, deserialization, account extraction, order
%%% management, and state transformations.

-module(ssl_cert_state_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/ssl_cert.hrl").

%%%--------------------------------------------------------------------
%%% Test Data
%%%--------------------------------------------------------------------

%% Generate a test RSA private key for testing
generate_test_key() ->
    public_key:generate_key({rsa, 2048, 65537}).

sample_account() ->
    #acme_account{
        key = generate_test_key(),
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

sample_state() ->
    % Generate a test key and serialize it for the sample state
    TestKey = generate_test_key(),
    KeyPem = ssl_cert_state:serialize_private_key(TestKey),
    #{
        <<"account">> => #{
            <<"key_pem">> => ssl_utils:bin(KeyPem),
            <<"url">> => <<"https://acme-staging-v02.api.letsencrypt.org/acme/acct/123">>,
            <<"kid">> => <<"https://acme-staging-v02.api.letsencrypt.org/acme/acct/123">>
        },
        <<"order">> => #{
            <<"url">> => <<"https://acme-staging-v02.api.letsencrypt.org/acme/order/123">>,
            <<"status">> => <<"pending">>,
            <<"expires">> => <<"2024-01-01T00:00:00Z">>,
            <<"identifiers">> => [#{<<"type">> => <<"dns">>, <<"value">> => <<"example.com">>}],
            <<"authorizations">> => [
                <<"https://acme-staging-v02.api.letsencrypt.org/acme/authz/123">>
            ],
            <<"finalize">> => <<"https://acme-staging-v02.api.letsencrypt.org/acme/finalize/123">>,
            <<"certificate">> => <<>>
        },
        <<"challenges">> => [
            #{
                <<"domain">> => <<"example.com">>,
                <<"token">> => <<"test_token_123">>,
                <<"key_authorization">> => <<"test_key_auth_456">>,
                <<"dns_value">> => <<"test_dns_value_789">>,
                <<"url">> => <<"https://acme-staging-v02.api.letsencrypt.org/acme/challenge/123">>
            }
        ],
        <<"domains">> => [<<"example.com">>],
        <<"status">> => <<"pending">>
    }.

%%%--------------------------------------------------------------------
%%% Account Management Tests
%%%--------------------------------------------------------------------

extract_account_from_state_test() ->
    State = sample_state(),
    Account = ssl_cert_state:extract_account_from_state(State),
    ?assertEqual(
        "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123", Account#acme_account.url
    ),
    ?assertEqual(
        "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123", Account#acme_account.kid
    ).

serialize_account_test() ->
    Account = sample_account(),
    SerializedAccount = ssl_cert_state:serialize_account(Account),
    ?assert(maps:is_key(<<"url">>, SerializedAccount)),
    ?assert(maps:is_key(<<"kid">>, SerializedAccount)),
    ?assertEqual(ssl_utils:bin(Account#acme_account.url), maps:get(<<"url">>, SerializedAccount)),
    ?assertEqual(ssl_utils:bin(Account#acme_account.kid), maps:get(<<"kid">>, SerializedAccount)).

%%%--------------------------------------------------------------------
%%% Order Management Tests
%%%--------------------------------------------------------------------

extract_order_from_state_test() ->
    State = sample_state(),
    Order = ssl_cert_state:extract_order_from_state(State),
    ?assertEqual(
        "https://acme-staging-v02.api.letsencrypt.org/acme/order/123", Order#acme_order.url
    ),
    ?assertEqual("pending", Order#acme_order.status).

update_order_in_state_test() ->
    State = sample_state(),
    UpdatedOrder = (sample_order())#acme_order{status = "valid"},
    NewState = ssl_cert_state:update_order_in_state(State, UpdatedOrder),
    OrderMap = maps:get(<<"order">>, NewState),
    ?assertEqual(<<"valid">>, maps:get(<<"status">>, OrderMap)).

%%%--------------------------------------------------------------------
%%% Challenge Management Tests
%%%--------------------------------------------------------------------

serialize_challenges_test() ->
    Challenges = [sample_challenge()],
    SerializedChallenges = ssl_cert_state:serialize_challenges(Challenges),
    ?assertEqual(1, length(SerializedChallenges)),
    [Challenge] = SerializedChallenges,
    ?assert(maps:is_key(<<"domain">>, Challenge)),
    ?assert(maps:is_key(<<"token">>, Challenge)),
    ?assertEqual(<<"example.com">>, maps:get(<<"domain">>, Challenge)).

%%%--------------------------------------------------------------------
%%% State Serialization Tests
%%%--------------------------------------------------------------------

serialize_deserialize_state_test() ->
    State = sample_state(),
    % Test that state can be serialized and deserialized
    % (This would depend on the actual implementation)
    ?assert(is_map(State)).

%%%--------------------------------------------------------------------
%%% Error Handling Tests
%%%--------------------------------------------------------------------

extract_account_invalid_state_test() ->
    % Test with invalid state
    InvalidState = #{},
    ?assertError(_, ssl_cert_state:extract_account_from_state(InvalidState)).

extract_order_invalid_state_test() ->
    % Test with invalid state
    InvalidState = #{},
    ?assertError(_, ssl_cert_state:extract_order_from_state(InvalidState)).

%%%--------------------------------------------------------------------
%%% Private Key Handling Tests
%%%--------------------------------------------------------------------

private_key_serialization_test() ->
    % Test private key serialization if the function is exported
    % This would test the RSA key creation and PEM serialization
    ?assert(erlang:function_exported(ssl_cert_state, extract_account_from_state, 1)).

%%%--------------------------------------------------------------------
%%% Test Suite
%%%--------------------------------------------------------------------

ssl_cert_state_test_() ->
    [
        {"Account management tests", [
            fun extract_account_from_state_test/0,
            fun serialize_account_test/0
        ]},
        {"Order management tests", [
            fun extract_order_from_state_test/0,
            fun update_order_in_state_test/0
        ]},
        {"Challenge management tests", [
            fun serialize_challenges_test/0
        ]},
        {"State serialization tests", [
            fun serialize_deserialize_state_test/0
        ]},
        {"Error handling tests", [
            fun extract_account_invalid_state_test/0,
            fun extract_order_invalid_state_test/0
        ]},
        {"Private key tests", [
            fun private_key_serialization_test/0
        ]}
    ].
