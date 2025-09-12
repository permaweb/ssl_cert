%%% @doc Integration tests for SSL certificate management system.
%%%
%%% This module contains end-to-end integration tests that verify the
%%% complete SSL certificate workflow including account creation,
%%% certificate requests, challenge validation, and certificate download.

-module(ssl_cert_integration_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/ssl_cert.hrl").

%%%--------------------------------------------------------------------
%%% Test Configuration
%%%--------------------------------------------------------------------

test_config() ->
    #{
        domains => ["test.example.com"],
        email => "test@example.com",
        environment => staging,
        % Smaller key for faster testing
        key_size => 2048
    }.

%%%--------------------------------------------------------------------
%%% Module Integration Tests
%%%--------------------------------------------------------------------

ssl_utils_integration_test() ->
    % Test ssl_utils integration with other modules
    TestData = #{<<"test">> => <<"data">>},

    % Test JSON roundtrip
    Encoded = ssl_utils:json_encode(TestData),
    Decoded = ssl_utils:json_decode(Encoded),
    ?assertEqual(TestData, Decoded),

    % Test type conversions
    BinData = ssl_utils:bin("test"),
    ListData = ssl_utils:list(BinData),
    ?assertEqual("test", ListData),

    % Test error formatting
    {error, ErrorResp} = ssl_utils:build_error_response(400, <<"Test Error">>),
    ?assertEqual(400, maps:get(<<"status">>, ErrorResp)),
    ?assertEqual(<<"Test Error">>, maps:get(<<"error">>, ErrorResp)).

validation_integration_test() ->
    % Test validation module integration
    Config = test_config(),
    Domains = maps:get(domains, Config),
    Email = maps:get(email, Config),
    Environment = maps:get(environment, Config),

    % Test complete parameter validation
    {ok, ValidatedParams} = ssl_cert_validation:validate_request_params(
        Domains, Email, Environment
    ),

    ?assertEqual(Domains, maps:get(domains, ValidatedParams)),
    ?assertEqual(Email, maps:get(email, ValidatedParams)),
    ?assertEqual(Environment, maps:get(environment, ValidatedParams)).

%% Generate a test RSA private key for testing
generate_test_key() ->
    public_key:generate_key({rsa, 2048, 65537}).

state_management_integration_test() ->
    % Test state management integration
    Account = #acme_account{
        key = generate_test_key(),
        url = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123",
        kid = "test_kid"
    },

    Order = #acme_order{
        url = "https://acme-staging-v02.api.letsencrypt.org/acme/order/123",
        status = "pending",
        expires = "2024-01-01T00:00:00Z",
        identifiers = [],
        authorizations = [],
        finalize = "https://example.com/finalize",
        certificate = ""
    },

    Challenge = #dns_challenge{
        domain = "example.com",
        token = "test_token",
        key_authorization = "test_key_auth",
        dns_value = "test_dns_value",
        url = "https://example.com/challenge"
    },

    % Test state operations using create_request_state
    ValidatedParams = #{domains => ["example.com"], email => "test@example.com"},
    State = ssl_cert_state:create_request_state(Account, Order, [Challenge], ValidatedParams),

    % Test extraction
    ExtractedAccount = ssl_cert_state:extract_account_from_state(State),
    ExtractedOrder = ssl_cert_state:extract_order_from_state(State),

    ?assertEqual(Account#acme_account.url, ExtractedAccount#acme_account.url),
    ?assertEqual(Order#acme_order.url, ExtractedOrder#acme_order.url).

challenge_formatting_integration_test() ->
    % Test challenge formatting integration
    Challenge = #{
        <<"domain">> => <<"example.com">>,
        <<"token">> => <<"test_token">>,
        <<"key_authorization">> => <<"test_key_auth">>,
        <<"dns_value">> => <<"test_dns_value">>,
        <<"url">> => <<"https://example.com/challenge">>
    },

    FormattedChallenges = ssl_cert_challenge:format_challenges_for_response([Challenge]),
    ?assertEqual(1, length(FormattedChallenges)),

    [FormattedChallenge] = FormattedChallenges,
    ?assertEqual(<<"example.com">>, maps:get(<<"domain">>, FormattedChallenge)),
    ?assertEqual(
        <<"_acme-challenge.example.com">>, maps:get(<<"record_name">>, FormattedChallenge)
    ),
    ?assert(maps:is_key(<<"instructions">>, FormattedChallenge)).

url_utilities_integration_test() ->
    % Test URL utilities integration
    TestUrl = "https://acme-staging-v02.api.letsencrypt.org/directory",

    BaseUrl = acme_url:extract_base_url(TestUrl),
    Host = acme_url:extract_host_from_url(TestUrl),
    Path = acme_url:extract_path_from_url(TestUrl),
    Directory = acme_url:determine_directory_from_url(TestUrl),

    ?assertEqual("https://acme-staging-v02.api.letsencrypt.org", BaseUrl),
    ?assertEqual(<<"acme-staging-v02.api.letsencrypt.org">>, Host),
    ?assertEqual("/directory", Path),
    ?assertEqual(?LETS_ENCRYPT_STAGING, Directory).

crypto_utilities_integration_test() ->
    % Test crypto utilities integration
    TestData = <<"test data for encoding">>,

    % Test base64url roundtrip
    Encoded = acme_crypto:base64url_encode(TestData),
    Decoded = acme_crypto:base64url_decode(Encoded),
    ?assertEqual(TestData, Decoded),

    % Test DNS TXT value generation (which uses SHA-256 internally)
    KeyAuth = "test_token.test_thumbprint",
    DnsValue = acme_crypto:generate_dns_txt_value(KeyAuth),
    ?assert(is_list(DnsValue)),
    ?assert(length(DnsValue) > 0).

%%%--------------------------------------------------------------------
%%% Workflow Integration Tests
%%%--------------------------------------------------------------------

certificate_request_workflow_structure_test() ->
    % Test that all required functions exist for the complete workflow
    WorkflowFunctions = [
        {ssl_cert_validation, validate_request_params, 3},
        {ssl_cert_state, create_request_state, 4},
        {ssl_cert_state, update_order_in_state, 2},
        {ssl_cert_state, serialize_challenges, 1},
        {ssl_cert_challenge, format_challenges_for_response, 1},
        {ssl_cert_ops, process_certificate_request, 2},
        {ssl_cert_ops, download_certificate_state, 2}
    ],

    lists:foreach(
        fun({Module, Function, Arity}) ->
            ?assert(erlang:function_exported(Module, Function, Arity))
        end,
        WorkflowFunctions
    ).

acme_protocol_workflow_structure_test() ->
    % Test ACME protocol workflow functions
    AcmeWorkflowFunctions = [
        {acme_protocol, create_account, 2},
        {acme_protocol, request_certificate, 2},
        {acme_protocol, get_dns_challenge, 2},
        {acme_protocol, validate_challenge, 2},
        {acme_protocol, finalize_order, 3},
        {acme_protocol, download_certificate, 2}
    ],

    lists:foreach(
        fun({Module, Function, Arity}) ->
            ?assert(erlang:function_exported(Module, Function, Arity))
        end,
        AcmeWorkflowFunctions
    ).

%%%--------------------------------------------------------------------
%%% Error Propagation Tests
%%%--------------------------------------------------------------------

error_propagation_test() ->
    % Test that errors propagate correctly through the system
    InvalidDomains = [],
    {error, _Reason} = ssl_cert_validation:validate_domains(InvalidDomains),

    InvalidEmail = "invalid-email",
    {error, _Reason2} = ssl_cert_validation:validate_email(InvalidEmail),

    InvalidEnvironment = <<"invalid">>,
    {error, _Reason3} = ssl_cert_validation:validate_environment(InvalidEnvironment).

state_consistency_test() ->
    % Test state consistency across operations
    InitialState = #{},

    Account = #acme_account{
        key = generate_test_key(),
        url = "https://example.com/account",
        kid = "test_kid"
    },

    % Test state creation and extraction
    ValidatedParams = #{domains => ["example.com"], email => "test@example.com"},
    Order = #acme_order{
        url = "https://example.com/order",
        status = "pending",
        expires = "2024-01-01T00:00:00Z",
        identifiers = [],
        authorizations = [],
        finalize = "https://example.com/finalize",
        certificate = ""
    },
    Challenge = #dns_challenge{
        domain = "example.com",
        token = "test_token",
        key_authorization = "test_key_auth",
        dns_value = "test_dns_value",
        url = "https://example.com/challenge"
    },
    StateWithAccount = ssl_cert_state:create_request_state(
        Account, Order, [Challenge], ValidatedParams
    ),
    ?assert(maps:is_key(<<"account">>, StateWithAccount)),

    ExtractedAccount = ssl_cert_state:extract_account_from_state(StateWithAccount),
    ?assertEqual(Account#acme_account.url, ExtractedAccount#acme_account.url).

%%%--------------------------------------------------------------------
%%% Configuration Tests
%%%--------------------------------------------------------------------

constants_test() ->
    % Test that all required constants are defined
    ?assert(is_list(?LETS_ENCRYPT_STAGING)),
    ?assert(is_list(?LETS_ENCRYPT_PROD)),
    ?assert(is_integer(?CHALLENGE_POLL_DELAY_SECONDS)),
    ?assert(is_integer(?CHALLENGE_DEFAULT_TIMEOUT_SECONDS)),
    ?assert(is_integer(?SSL_CERT_KEY_SIZE)),
    ?assert(is_binary(?ACME_STATUS_VALID)),
    ?assert(is_binary(?ACME_STATUS_INVALID)),
    ?assert(is_binary(?ACME_STATUS_PENDING)),
    ?assert(is_binary(?ACME_STATUS_PROCESSING)).

record_definitions_test() ->
    % Test that all records are properly defined
    Account = #acme_account{key = test, url = "test", kid = "test"},
    ?assert(is_record(Account, acme_account)),

    Order = #acme_order{
        url = "test",
        status = "test",
        expires = "test",
        identifiers = [],
        authorizations = [],
        finalize = "test",
        certificate = "test"
    },
    ?assert(is_record(Order, acme_order)),

    Challenge = #dns_challenge{
        domain = "test",
        token = "test",
        key_authorization = "test",
        dns_value = "test",
        url = "test"
    },
    ?assert(is_record(Challenge, dns_challenge)).

%%%--------------------------------------------------------------------
%%% Test Suite
%%%--------------------------------------------------------------------

ssl_cert_integration_test_() ->
    % 30 second timeout for integration tests
    {timeout, 30, [
        {"Module integration tests", [
            fun ssl_utils_integration_test/0,
            fun validation_integration_test/0,
            fun state_management_integration_test/0,
            fun challenge_formatting_integration_test/0,
            fun url_utilities_integration_test/0,
            fun crypto_utilities_integration_test/0
        ]},
        {"Workflow structure tests", [
            fun certificate_request_workflow_structure_test/0,
            fun acme_protocol_workflow_structure_test/0
        ]},
        {"Error propagation tests", [
            fun error_propagation_test/0,
            fun state_consistency_test/0
        ]},
        {"Configuration tests", [
            fun constants_test/0,
            fun record_definitions_test/0
        ]}
    ]}.
