%%% @doc Tests for ssl_cert_challenge module.
%%%
%%% This module contains comprehensive tests for SSL certificate challenge
%%% management including DNS challenge validation, polling, timeout handling,
%%% and response formatting.

-module(ssl_cert_challenge_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/ssl_cert.hrl").

%%%--------------------------------------------------------------------
%%% Test Data
%%%--------------------------------------------------------------------

sample_challenge() ->
    #dns_challenge{
        domain = "example.com",
        token = "test_token_123",
        key_authorization = "test_key_auth_456",
        dns_value = "test_dns_value_789",
        url = "https://acme-staging-v02.api.letsencrypt.org/acme/challenge/123"
    }.

sample_challenge_map() ->
    #{
        <<"domain">> => <<"example.com">>,
        <<"token">> => <<"test_token_123">>,
        <<"key_authorization">> => <<"test_key_auth_456">>,
        <<"dns_value">> => <<"test_dns_value_789">>,
        <<"url">> => <<"https://acme-staging-v02.api.letsencrypt.org/acme/challenge/123">>
    }.

sample_validation_results() ->
    [
        #{<<"domain">> => <<"example.com">>, <<"status">> => ?ACME_STATUS_VALID},
        #{<<"domain">> => <<"test.org">>, <<"status">> => ?ACME_STATUS_VALID}
    ].

sample_mixed_validation_results() ->
    [
        #{<<"domain">> => <<"example.com">>, <<"status">> => ?ACME_STATUS_VALID},
        #{
            <<"domain">> => <<"test.org">>,
            <<"status">> => ?ACME_STATUS_INVALID,
            <<"error">> => <<"Failed">>
        }
    ].

%%%--------------------------------------------------------------------
%%% Challenge Formatting Tests
%%%--------------------------------------------------------------------

format_challenges_for_response_test() ->
    Challenges = [sample_challenge_map()],
    Result = ssl_cert_challenge:format_challenges_for_response(Challenges),
    ?assertEqual(1, length(Result)),
    [FormattedChallenge] = Result,
    ?assertEqual(<<"example.com">>, maps:get(<<"domain">>, FormattedChallenge)),
    ?assertEqual(
        <<"_acme-challenge.example.com">>, maps:get(<<"record_name">>, FormattedChallenge)
    ),
    ?assertEqual(<<"test_dns_value_789">>, maps:get(<<"record_value">>, FormattedChallenge)),
    ?assert(maps:is_key(<<"instructions">>, FormattedChallenge)).

format_challenges_with_record_test() ->
    Challenges = [sample_challenge()],
    Result = ssl_cert_challenge:format_challenges_for_response(Challenges),
    ?assertEqual(1, length(Result)),
    [FormattedChallenge] = Result,
    ?assertEqual(<<"example.com">>, maps:get(<<"domain">>, FormattedChallenge)).

format_challenges_instructions_test() ->
    Challenges = [sample_challenge_map()],
    [Result] = ssl_cert_challenge:format_challenges_for_response(Challenges),
    Instructions = maps:get(<<"instructions">>, Result),
    ?assert(maps:is_key(<<"cloudflare">>, Instructions)),
    ?assert(maps:is_key(<<"route53">>, Instructions)),
    ?assert(maps:is_key(<<"manual">>, Instructions)).

%%%--------------------------------------------------------------------
%%% Challenge Extraction Tests
%%%--------------------------------------------------------------------

extract_challenge_info_map_test() ->
    ChallengeMap = sample_challenge_map(),
    {Domain, ChallengeRecord} = ssl_cert_challenge:extract_challenge_info(ChallengeMap),
    ?assertEqual("example.com", Domain),
    ?assertEqual("example.com", ChallengeRecord#dns_challenge.domain),
    ?assertEqual("test_token_123", ChallengeRecord#dns_challenge.token).

extract_challenge_info_record_test() ->
    ChallengeRecord = sample_challenge(),
    {Domain, ExtractedRecord} = ssl_cert_challenge:extract_challenge_info(ChallengeRecord),
    ?assertEqual("example.com", Domain),
    ?assertEqual(ChallengeRecord, ExtractedRecord).

extract_challenge_info_atom_keys_test() ->
    ChallengeMap = #{
        domain => "test.org",
        token => "token_456",
        key_authorization => "key_auth_789",
        dns_value => "dns_value_012",
        url => "https://example.com/challenge"
    },
    {Domain, ChallengeRecord} = ssl_cert_challenge:extract_challenge_info(ChallengeMap),
    ?assertEqual("test.org", Domain),
    ?assertEqual("test.org", ChallengeRecord#dns_challenge.domain).

%%%--------------------------------------------------------------------
%%% Helper Function Tests
%%%--------------------------------------------------------------------

all_challenges_valid_test() ->
    ValidResults = sample_validation_results(),
    ?assert(ssl_cert_challenge:all_challenges_valid(ValidResults)).

all_challenges_valid_mixed_test() ->
    MixedResults = sample_mixed_validation_results(),
    ?assertNot(ssl_cert_challenge:all_challenges_valid(MixedResults)).

all_challenges_valid_empty_test() ->
    ?assert(ssl_cert_challenge:all_challenges_valid([])).

merge_validation_results_test() ->
    Original = [#{<<"domain">> => <<"example.com">>, <<"status">> => ?ACME_STATUS_PENDING}],
    Retry = [#{<<"domain">> => <<"example.com">>, <<"status">> => ?ACME_STATUS_VALID}],
    Merged = ssl_cert_challenge:merge_validation_results(Original, Retry),
    ?assertEqual(1, length(Merged)),
    [Result] = Merged,
    ?assertEqual(?ACME_STATUS_VALID, maps:get(<<"status">>, Result)).

merge_validation_results_different_domains_test() ->
    Original = [#{<<"domain">> => <<"example.com">>, <<"status">> => ?ACME_STATUS_VALID}],
    Retry = [#{<<"domain">> => <<"test.org">>, <<"status">> => ?ACME_STATUS_VALID}],
    Merged = ssl_cert_challenge:merge_validation_results(Original, Retry),
    ?assertEqual(2, length(Merged)).

results_to_domain_map_test() ->
    Results = sample_validation_results(),
    DomainMap = ssl_cert_challenge:results_to_domain_map(Results),
    ?assertEqual(2, maps:size(DomainMap)),
    ?assert(maps:is_key(<<"example.com">>, DomainMap)),
    ?assert(maps:is_key(<<"test.org">>, DomainMap)).

extract_domain_bin_test() ->
    % Test with binary key map
    Challenge1 = #{<<"domain">> => <<"example.com">>},
    ?assertEqual(<<"example.com">>, ssl_cert_challenge:extract_domain_bin(Challenge1)),

    % Test with atom key map
    Challenge2 = #{domain => "test.org"},
    ?assertEqual(<<"test.org">>, ssl_cert_challenge:extract_domain_bin(Challenge2)),

    % Test with invalid challenge
    Challenge3 = #{<<"other">> => <<"value">>},
    ?assertEqual(<<>>, ssl_cert_challenge:extract_domain_bin(Challenge3)).

%%%--------------------------------------------------------------------
%%% Mock-based Integration Tests
%%%--------------------------------------------------------------------

% Note: These would require mocking the ACME client functions
% For now, we test the structure and exported functions

validate_challenges_with_timeout_structure_test() ->
    % Test that the function exists and has correct arity
    ?assert(erlang:function_exported(ssl_cert_challenge, validate_challenges_with_timeout, 3)).

poll_challenge_status_structure_test() ->
    % Test that the function exists and has correct arity
    ?assert(erlang:function_exported(ssl_cert_challenge, poll_challenge_status, 6)).

poll_order_until_valid_structure_test() ->
    % Test that the function exists and has correct arity
    ?assert(erlang:function_exported(ssl_cert_challenge, poll_order_until_valid, 3)).

validate_dns_challenges_state_structure_test() ->
    % Test that the function exists and has correct arity
    ?assert(erlang:function_exported(ssl_cert_challenge, validate_dns_challenges_state, 2)).

%%%--------------------------------------------------------------------
%%% Error Handling Tests
%%%--------------------------------------------------------------------

format_challenges_empty_list_test() ->
    Result = ssl_cert_challenge:format_challenges_for_response([]),
    ?assertEqual([], Result).

extract_challenge_info_invalid_test() ->
    % Test with completely invalid input
    ?assertError(_, ssl_cert_challenge:extract_challenge_info(invalid_input)).

%%%--------------------------------------------------------------------
%%% Test Suite
%%%--------------------------------------------------------------------

ssl_cert_challenge_test_() ->
    [
        {"Challenge formatting tests", [
            fun format_challenges_for_response_test/0,
            fun format_challenges_with_record_test/0,
            fun format_challenges_instructions_test/0,
            fun format_challenges_empty_list_test/0
        ]},
        {"Challenge extraction tests", [
            fun extract_challenge_info_map_test/0,
            fun extract_challenge_info_record_test/0,
            fun extract_challenge_info_atom_keys_test/0,
            fun extract_challenge_info_invalid_test/0
        ]},
        {"Helper function tests", [
            fun all_challenges_valid_test/0,
            fun all_challenges_valid_mixed_test/0,
            fun all_challenges_valid_empty_test/0,
            fun merge_validation_results_test/0,
            fun merge_validation_results_different_domains_test/0,
            fun results_to_domain_map_test/0,
            fun extract_domain_bin_test/0
        ]},
        {"Structure tests", [
            fun validate_challenges_with_timeout_structure_test/0,
            fun poll_challenge_status_structure_test/0,
            fun poll_order_until_valid_structure_test/0,
            fun validate_dns_challenges_state_structure_test/0
        ]}
    ].
