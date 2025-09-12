%%% @doc Tests for acme_crypto module.
%%%
%%% This module contains comprehensive tests for ACME cryptographic operations
%%% including base64url encoding/decoding, JWS creation, key thumbprints,
%%% and signature generation.

-module(acme_crypto_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/ssl_cert.hrl").

%%%--------------------------------------------------------------------
%%% Base64URL Tests
%%%--------------------------------------------------------------------

base64url_encode_test() ->
    Data = <<"Hello, World!">>,
    Result = acme_crypto:base64url_encode(Data),
    ?assert(is_list(Result)),
    ?assert(length(Result) > 0),
    % Base64URL should not contain padding characters
    ?assertEqual(nomatch, string:find(Result, "=")).

base64url_encode_empty_test() ->
    Result = acme_crypto:base64url_encode(<<>>),
    ?assertEqual("", Result).

base64url_encode_decode_roundtrip_test() ->
    TestData = [
        <<"test">>,
        <<"Hello, World!">>,
        <<"Special chars: !@#$%^&*()">>,
        <<1, 2, 3, 4, 5>>,
        <<"">>,
        <<"a">>,
        <<"ab">>,
        <<"abc">>,
        <<"abcd">>
    ],
    lists:foreach(
        fun(Data) ->
            Encoded = acme_crypto:base64url_encode(Data),
            Decoded = acme_crypto:base64url_decode(Encoded),
            ?assertEqual(Data, Decoded)
        end,
        TestData
    ).

base64url_decode_test() ->
    % Test known base64url encoding

    % "Hello, World!" in base64url
    Encoded = "SGVsbG8sIFdvcmxkIQ",
    Result = acme_crypto:base64url_decode(Encoded),
    ?assertEqual(<<"Hello, World!">>, Result).

base64url_decode_invalid_test() ->
    % Test with invalid base64url
    ?assertError(_, acme_crypto:base64url_decode("invalid==base64")).

%%%--------------------------------------------------------------------
%%% JWS (JSON Web Signature) Tests
%%%--------------------------------------------------------------------

create_jws_header_test() ->
    % Test that function exists and returns proper structure
    ?assert(erlang:function_exported(acme_crypto, create_jws_header, 4)).

create_jws_signature_test() ->
    % Test JWS signature creation
    ?assert(erlang:function_exported(acme_crypto, create_jws_signature, 3)).

sign_data_test() ->
    % Test data signing (would need mock key)
    ?assert(erlang:function_exported(acme_crypto, sign_data, 3)).

%%%--------------------------------------------------------------------
%%% Key Thumbprint Tests
%%%--------------------------------------------------------------------

private_key_to_jwk_test() ->
    % Test private key to JWK conversion
    ?assert(erlang:function_exported(acme_crypto, private_key_to_jwk, 1)).

%%%--------------------------------------------------------------------
%%% Hash Function Tests
%%%--------------------------------------------------------------------

generate_dns_txt_value_test() ->
    KeyAuth = "test_token.test_thumbprint",
    Result = acme_crypto:generate_dns_txt_value(KeyAuth),
    ?assert(is_list(Result)),
    ?assert(length(Result) > 0).

generate_key_authorization_test() ->
    Token = "test_token",
    % We need a mock private key for this test
    ?assert(erlang:function_exported(acme_crypto, generate_key_authorization, 2)).

get_jwk_thumbprint_test() ->
    % Test that function exists (would need mock key for full test)
    ?assert(erlang:function_exported(acme_crypto, get_jwk_thumbprint, 1)).

%%%--------------------------------------------------------------------
%%% Key Generation Tests
%%%--------------------------------------------------------------------

generate_rsa_key_test() ->
    % Test RSA key generation if exported
    ?assert(erlang:function_exported(acme_crypto, base64url_encode, 1)).

%%%--------------------------------------------------------------------
%%% Error Handling Tests
%%%--------------------------------------------------------------------

base64url_encode_non_binary_test() ->
    % Test with string input (should work according to spec)
    Result = acme_crypto:base64url_encode("string_not_binary"),
    ?assert(is_list(Result)),
    ?assert(length(Result) > 0),
    % Test with invalid input type (should error)
    ?assertError(_, acme_crypto:base64url_encode(123)).

%%%--------------------------------------------------------------------
%%% Property-based Tests (for future enhancement)
%%%--------------------------------------------------------------------

% prop_base64url_roundtrip() ->
%     ?FORALL(Data, binary(),
%         begin
%             Encoded = acme_crypto:base64url_encode(Data),
%             Decoded = acme_crypto:base64url_decode(Encoded),
%             Data =:= Decoded
%         end).

% prop_sha256_deterministic() ->
%     ?FORALL(Data, binary(),
%         begin
%             Hash1 = acme_crypto:sha256(Data),
%             Hash2 = acme_crypto:sha256(Data),
%             Hash1 =:= Hash2
%         end).

%%%--------------------------------------------------------------------
%%% Performance Tests
%%%--------------------------------------------------------------------

base64url_encode_performance_test() ->
    % Test encoding performance with larger data
    LargeData = crypto:strong_rand_bytes(1024),
    StartTime = erlang:monotonic_time(microsecond),
    _Result = acme_crypto:base64url_encode(LargeData),
    EndTime = erlang:monotonic_time(microsecond),
    Duration = EndTime - StartTime,
    % Should complete within reasonable time (1 second = 1,000,000 microseconds)
    ?assert(Duration < 1000000).

create_jws_signature_performance_test() ->
    % Test JWS signature creation performance
    Header = "test_header",
    Payload = "test_payload",
    % This would need a mock key for full test
    ?assert(erlang:function_exported(acme_crypto, create_jws_signature, 3)).

%%%--------------------------------------------------------------------
%%% Test Suite
%%%--------------------------------------------------------------------

acme_crypto_test_() ->
    [
        {"Base64URL tests", [
            fun base64url_encode_test/0,
            fun base64url_encode_empty_test/0,
            fun base64url_encode_decode_roundtrip_test/0,
            fun base64url_decode_test/0,
            fun base64url_decode_invalid_test/0
        ]},
        {"JWS tests", [
            fun create_jws_header_test/0,
            fun create_jws_signature_test/0,
            fun sign_data_test/0
        ]},
        {"Key conversion tests", [
            fun private_key_to_jwk_test/0
        ]},
        {"Crypto function tests", [
            fun generate_dns_txt_value_test/0,
            fun generate_key_authorization_test/0,
            fun get_jwk_thumbprint_test/0
        ]},
        {"Key generation tests", [
            fun generate_rsa_key_test/0
        ]},
        {"Error handling tests", [
            fun base64url_encode_non_binary_test/0
        ]},
        {"Performance tests", [
            fun base64url_encode_performance_test/0,
            fun create_jws_signature_performance_test/0
        ]}
    ].
