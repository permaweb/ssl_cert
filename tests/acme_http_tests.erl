%%% @doc Tests for acme_http module.
%%%
%%% This module contains comprehensive tests for ACME HTTP operations
%%% including JWS requests, directory fetching, header processing,
%%% and response handling.

-module(acme_http_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/ssl_cert.hrl").

%%%--------------------------------------------------------------------
%%% Test Data
%%%--------------------------------------------------------------------

sample_headers_proplist() ->
    [
        {"content-type", "application/json"},
        {"location", "https://example.com/resource/123"},
        {"replay-nonce", "abc123def456"}
    ].

sample_headers_map() ->
    #{
        <<"content-type">> => <<"application/json">>,
        <<"location">> => <<"https://example.com/resource/123">>,
        <<"replay-nonce">> => <<"abc123def456">>
    }.

sample_response_body() ->
    #{
        <<"status">> => <<"valid">>,
        <<"identifier">> => #{
            <<"type">> => <<"dns">>,
            <<"value">> => <<"example.com">>
        }
    }.

%%%--------------------------------------------------------------------
%%% Header Processing Tests
%%%--------------------------------------------------------------------

extract_location_header_proplist_test() ->
    Headers = sample_headers_proplist(),
    Result = acme_http:extract_location_header(Headers),
    ?assertEqual("https://example.com/resource/123", Result).

extract_location_header_map_test() ->
    Headers = sample_headers_map(),
    Result = acme_http:extract_location_header(Headers),
    ?assertEqual("https://example.com/resource/123", Result).

extract_location_header_missing_test() ->
    Headers = [{"content-type", "application/json"}],
    Result = acme_http:extract_location_header(Headers),
    ?assertEqual(undefined, Result).

extract_location_header_case_insensitive_test() ->
    Headers = [
        {"Content-Type", "application/json"},
        {"Location", "https://example.com/resource/123"}
    ],
    Result = acme_http:extract_location_header(Headers),
    ?assertEqual("https://example.com/resource/123", Result).

extract_replay_nonce_proplist_test() ->
    Headers = sample_headers_proplist(),
    Result = acme_http:extract_nonce_header(Headers),
    ?assertEqual("abc123def456", Result).

extract_replay_nonce_map_test() ->
    Headers = sample_headers_map(),
    Result = acme_http:extract_nonce_header(Headers),
    ?assertEqual("abc123def456", Result).

extract_replay_nonce_missing_test() ->
    Headers = [{"content-type", "application/json"}],
    Result = acme_http:extract_nonce_header(Headers),
    ?assertEqual(undefined, Result).

%%%--------------------------------------------------------------------
%%% Response Processing Tests
%%%--------------------------------------------------------------------

process_http_response_success_test() ->
    StatusCode = 200,
    Headers = sample_headers_proplist(),
    Body = ssl_utils:json_encode(sample_response_body()),

    {ok, Response, ResponseHeaders} = acme_http:process_http_response(StatusCode, Headers, Body),
    ?assert(is_map(Response)),
    ?assert(is_list(ResponseHeaders) orelse is_map(ResponseHeaders)).

process_http_response_created_test() ->
    StatusCode = 201,
    Headers = sample_headers_proplist(),
    Body = ssl_utils:json_encode(sample_response_body()),

    {ok, Response, _ResponseHeaders} = acme_http:process_http_response(StatusCode, Headers, Body),
    ?assert(is_map(Response)).

process_http_response_error_test() ->
    StatusCode = 400,
    Headers = [],
    ErrorBody = ssl_utils:json_encode(#{<<"error">> => <<"Bad Request">>}),

    {error, Reason} = acme_http:process_http_response(StatusCode, Headers, ErrorBody),
    ?assertMatch({http_error, 400, _}, Reason).

process_http_response_server_error_test() ->
    StatusCode = 500,
    Headers = [],
    Body = <<"Internal Server Error">>,

    {error, _Reason} = acme_http:process_http_response(StatusCode, Headers, Body).

%%%--------------------------------------------------------------------
%%% JWS Request Tests (Structure)
%%%--------------------------------------------------------------------

make_jws_request_structure_test() ->
    ?assert(erlang:function_exported(acme_http, make_jws_request, 4)).

make_jws_post_as_get_request_structure_test() ->
    ?assert(erlang:function_exported(acme_http, make_jws_post_as_get_request, 3)).

%%%--------------------------------------------------------------------
%%% Directory Fetching Tests
%%%--------------------------------------------------------------------

get_directory_structure_test() ->
    ?assert(erlang:function_exported(acme_http, get_directory, 1)).

% Note: Actual directory fetching would require network access or mocking

%%%--------------------------------------------------------------------
%%% Nonce Management Tests
%%%--------------------------------------------------------------------

get_fresh_nonce_structure_test() ->
    ?assert(erlang:function_exported(acme_http, get_fresh_nonce, 1)).

fallback_random_nonce_test() ->
    Nonce = acme_http:fallback_random_nonce(),
    ?assert(is_list(Nonce)),
    ?assert(length(Nonce) > 0),
    % Should be base64url encoded (no padding)
    ?assertEqual(nomatch, string:find(Nonce, "=")).

fallback_random_nonce_uniqueness_test() ->
    Nonce1 = acme_http:fallback_random_nonce(),
    Nonce2 = acme_http:fallback_random_nonce(),
    ?assertNotEqual(Nonce1, Nonce2).

%%%--------------------------------------------------------------------
%%% Helper Function Tests
%%%--------------------------------------------------------------------

make_acme_post_request_structure_test() ->
    % Test that the helper function exists (it's internal but we can test structure)
    ?assert(erlang:function_exported(acme_http, make_acme_post_request, 2)).

%%%--------------------------------------------------------------------
%%% Error Handling Tests
%%%--------------------------------------------------------------------

extract_location_header_malformed_test() ->
    % Test with malformed headers - should return undefined gracefully
    MalformedHeaders = "not_a_list_or_map",
    Result = acme_http:extract_location_header(MalformedHeaders),
    ?assertEqual(undefined, Result).

process_http_response_invalid_json_test() ->
    StatusCode = 200,
    Headers = [],
    InvalidBody = <<"invalid json">>,

    % Should handle invalid JSON gracefully and return empty map
    {ok, Response, _Headers} = acme_http:process_http_response(StatusCode, Headers, InvalidBody),
    ?assertEqual(#{}, Response).

%%%--------------------------------------------------------------------
%%% Integration Tests
%%%--------------------------------------------------------------------

header_extraction_integration_test() ->
    % Test complete header processing workflow
    Headers = [
        {"content-type", "application/json"},
        {"location", "https://example.com/account/123"},
        {"replay-nonce", "nonce123"},
        {"cache-control", "no-cache"}
    ],

    Location = acme_http:extract_location_header(Headers),
    Nonce = acme_http:extract_nonce_header(Headers),

    ?assertEqual("https://example.com/account/123", Location),
    ?assertEqual("nonce123", Nonce).

%%%--------------------------------------------------------------------
%%% Mock-based Tests (for future enhancement)
%%%--------------------------------------------------------------------

% Note: These would require mocking ssl_utils:http_post and other HTTP functions
% For comprehensive testing, consider using meck or similar mocking library

% mock_jws_request_test() ->
%     meck:new(ssl_utils),
%     meck:expect(ssl_utils, http_post, fun(_, _, _) ->
%         {ok, 200, [{"location", "https://example.com"}], <<"{\"status\":\"valid\"}">>}
%     end),
%
%     % Test actual JWS request
%     Result = acme_http:make_jws_request("https://example.com", #{}, test_key, "nonce"),
%     ?assertMatch({ok, _, _}, Result),
%
%     meck:unload(ssl_utils).

%%%--------------------------------------------------------------------
%%% Test Suite
%%%--------------------------------------------------------------------

acme_http_test_() ->
    [
        {"Header processing tests", [
            fun extract_location_header_proplist_test/0,
            fun extract_location_header_map_test/0,
            fun extract_location_header_missing_test/0,
            fun extract_location_header_case_insensitive_test/0,
            fun extract_replay_nonce_proplist_test/0,
            fun extract_replay_nonce_map_test/0,
            fun extract_replay_nonce_missing_test/0
        ]},
        {"Response processing tests", [
            fun process_http_response_success_test/0,
            fun process_http_response_created_test/0,
            fun process_http_response_error_test/0,
            fun process_http_response_server_error_test/0
        ]},
        {"JWS request structure tests", [
            fun make_jws_request_structure_test/0,
            fun make_jws_post_as_get_request_structure_test/0
        ]},
        {"Directory tests", [
            fun get_directory_structure_test/0
        ]},
        {"Nonce management tests", [
            fun get_fresh_nonce_structure_test/0,
            fun fallback_random_nonce_test/0,
            fun fallback_random_nonce_uniqueness_test/0
        ]},
        {"Helper function tests", [
            fun make_acme_post_request_structure_test/0
        ]},
        {"Error handling tests", [
            fun extract_location_header_malformed_test/0,
            fun process_http_response_invalid_json_test/0
        ]},
        {"Integration tests", [
            fun header_extraction_integration_test/0
        ]}
    ].
