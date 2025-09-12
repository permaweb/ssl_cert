%%% @doc Tests for ssl_utils module.
%%%
%%% This module contains comprehensive tests for the SSL utilities module,
%%% including type conversion, HTTP client functionality, JSON handling,
%%% and error formatting functions.

-module(ssl_utils_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/ssl_cert.hrl").

%%%--------------------------------------------------------------------
%%% Test Fixtures
%%%--------------------------------------------------------------------

setup() ->
    ok.

cleanup(_) ->
    ok.

%%%--------------------------------------------------------------------
%%% Type Conversion Tests
%%%--------------------------------------------------------------------

bin_conversion_test() ->
    ?assertEqual(<<"hello">>, ssl_utils:bin("hello")),
    ?assertEqual(<<"hello">>, ssl_utils:bin(<<"hello">>)),
    ?assertEqual(<<"123">>, ssl_utils:bin(123)),
    ?assertEqual(<<>>, ssl_utils:bin("")),
    ?assertEqual(<<>>, ssl_utils:bin(<<>>)).

list_conversion_test() ->
    ?assertEqual("hello", ssl_utils:list(<<"hello">>)),
    ?assertEqual("hello", ssl_utils:list("hello")),
    ?assertEqual("123", ssl_utils:list(123)),
    ?assertEqual("", ssl_utils:list(<<>>)),
    ?assertEqual("", ssl_utils:list("")).

%%%--------------------------------------------------------------------
%%% JSON Tests
%%%--------------------------------------------------------------------

json_encode_test() ->
    Map = #{<<"key">> => <<"value">>, <<"number">> => 42},
    Result = ssl_utils:json_encode(Map),
    ?assert(is_binary(Result)),
    ?assert(byte_size(Result) > 0).

json_decode_test() ->
    Json = <<"{\"key\":\"value\",\"number\":42}">>,
    Result = ssl_utils:json_decode(Json),
    ?assertEqual(#{<<"key">> => <<"value">>, <<"number">> => 42}, Result).

json_decode_with_opts_test() ->
    Json = <<"{\"key\":\"value\"}">>,
    Result = ssl_utils:json_decode(Json, []),
    ?assertEqual(#{<<"key">> => <<"value">>}, Result).

%%%--------------------------------------------------------------------
%%% Error Formatting Tests
%%%--------------------------------------------------------------------

build_error_response_test() ->
    {error, Response} = ssl_utils:build_error_response(400, <<"Bad Request">>),
    Expected = #{
        <<"status">> => 400,
        <<"error">> => <<"Bad Request">>
    },
    ?assertEqual(Expected, Response).

build_success_response_test() ->
    Body = #{<<"message">> => <<"Success">>},
    {ok, Response} = ssl_utils:build_success_response(200, Body),
    Expected = #{
        <<"status">> => 200,
        <<"body">> => Body
    },
    ?assertEqual(Expected, Response).

%%%--------------------------------------------------------------------
%%% HTTP Client Tests (Mock-based)
%%%--------------------------------------------------------------------

http_get_test() ->
    % This would require mocking the gun library
    % For now, we test the basic structure
    % Url = "https://httpbin.org/get",
    % Headers = [{"User-Agent", "Test"}],
    % Note: In a real test environment, you'd mock gun:open, gun:get, etc.
    % Result = ssl_utils:http_get(Url, Headers),
    % For now, just test that the function exists and has correct arity
    ?assert(erlang:function_exported(ssl_utils, http_get, 1)).

http_post_test() ->
    % Mock-based test would go here
    ?assert(erlang:function_exported(ssl_utils, http_post, 3)).

%%%--------------------------------------------------------------------
%%% Edge Cases and Error Handling
%%%--------------------------------------------------------------------

bin_with_invalid_input_test() ->
    % Test with atom
    ?assertEqual(<<"test">>, ssl_utils:bin(test)),
    % Test with list containing non-printable characters
    ?assertEqual(<<1, 2, 3>>, ssl_utils:bin([1, 2, 3])).

list_with_invalid_input_test() ->
    % Test with atom
    ?assertEqual("test", ssl_utils:list(test)),
    % Test with binary containing non-printable characters
    ?assertEqual([1, 2, 3], ssl_utils:list(<<1, 2, 3>>)).

json_decode_invalid_test() ->
    ?assertError(_, ssl_utils:json_decode(<<"invalid json">>)).

%%%--------------------------------------------------------------------
%%% Property-based Tests (if you want to add PropEr later)
%%%--------------------------------------------------------------------

% prop_bin_list_roundtrip() ->
%     ?FORALL(Data, oneof([binary(), list(char())]),
%         ssl_utils:list(ssl_utils:bin(Data)) =:= ssl_utils:list(Data)).

%%%--------------------------------------------------------------------
%%% Test Suite
%%%--------------------------------------------------------------------

ssl_utils_test_() ->
    {setup, fun setup/0, fun cleanup/1, [
        {"Type conversion tests", [
            fun bin_conversion_test/0,
            fun list_conversion_test/0
        ]},
        {"JSON handling tests", [
            fun json_encode_test/0,
            fun json_decode_test/0,
            fun json_decode_with_opts_test/0
        ]},
        {"Error formatting tests", [
            fun build_error_response_test/0,
            fun build_success_response_test/0
        ]},
        {"HTTP client tests", [
            fun http_get_test/0,
            fun http_post_test/0
        ]},
        {"Edge cases", [
            fun bin_with_invalid_input_test/0,
            fun list_with_invalid_input_test/0,
            fun json_decode_invalid_test/0
        ]}
    ]}.
