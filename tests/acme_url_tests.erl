%%% @doc Tests for acme_url module.
%%%
%%% This module contains comprehensive tests for ACME URL utilities
%%% including URL parsing, host extraction, path extraction, directory
%%% determination, and header processing.

-module(acme_url_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/ssl_cert.hrl").

%%%--------------------------------------------------------------------
%%% URL Parsing Tests
%%%--------------------------------------------------------------------

extract_base_url_with_scheme_test() ->
    Url = "https://acme-v02.api.letsencrypt.org/directory",
    Result = acme_url:extract_base_url(Url),
    ?assertEqual("https://acme-v02.api.letsencrypt.org", Result).

extract_base_url_without_scheme_test() ->
    Url = "acme-v02.api.letsencrypt.org/directory",
    Result = acme_url:extract_base_url(Url),
    ?assertEqual("https://acme-v02.api.letsencrypt.org", Result).

extract_base_url_http_test() ->
    Url = "http://example.com/path",
    Result = acme_url:extract_base_url(Url),
    ?assertEqual("http://example.com", Result).

extract_base_url_binary_test() ->
    Url = <<"https://example.com/path/to/resource">>,
    Result = acme_url:extract_base_url(Url),
    ?assertEqual("https://example.com", Result).

%%%--------------------------------------------------------------------
%%% Host Extraction Tests
%%%--------------------------------------------------------------------

extract_host_from_url_with_scheme_test() ->
    Url = "https://acme-v02.api.letsencrypt.org/directory",
    Result = acme_url:extract_host_from_url(Url),
    ?assertEqual(<<"acme-v02.api.letsencrypt.org">>, Result).

extract_host_from_url_without_scheme_test() ->
    Url = "example.com/path",
    Result = acme_url:extract_host_from_url(Url),
    ?assertEqual(<<"example.com">>, Result).

extract_host_from_url_binary_test() ->
    Url = <<"https://test.example.org/path">>,
    Result = acme_url:extract_host_from_url(Url),
    ?assertEqual(<<"test.example.org">>, Result).

extract_host_from_url_port_test() ->
    Url = "https://example.com:8443/path",
    Result = acme_url:extract_host_from_url(Url),
    ?assertEqual(<<"example.com:8443">>, Result).

%%%--------------------------------------------------------------------
%%% Path Extraction Tests
%%%--------------------------------------------------------------------

extract_path_from_url_with_scheme_test() ->
    Url = "https://acme-v02.api.letsencrypt.org/directory",
    Result = acme_url:extract_path_from_url(Url),
    ?assertEqual("/directory", Result).

extract_path_from_url_without_scheme_test() ->
    Url = "example.com/path/to/resource",
    Result = acme_url:extract_path_from_url(Url),
    ?assertEqual("/path/to/resource", Result).

extract_path_from_url_complex_path_test() ->
    Url = "https://api.example.com/v2/acme/new-order",
    Result = acme_url:extract_path_from_url(Url),
    ?assertEqual("/v2/acme/new-order", Result).

extract_path_from_url_root_test() ->
    Url = "https://example.com/",
    Result = acme_url:extract_path_from_url(Url),
    ?assertEqual("/", Result).

extract_path_from_url_no_path_test() ->
    Url = "https://example.com",
    Result = acme_url:extract_path_from_url(Url),
    ?assertEqual("/", Result).

%%%--------------------------------------------------------------------
%%% Directory Determination Tests
%%%--------------------------------------------------------------------

determine_directory_from_url_staging_test() ->
    StagingUrl = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123",
    Result = acme_url:determine_directory_from_url(StagingUrl),
    ?assertEqual(?LETS_ENCRYPT_STAGING, Result).

determine_directory_from_url_production_test() ->
    ProductionUrl = "https://acme-v02.api.letsencrypt.org/acme/acct/123",
    Result = acme_url:determine_directory_from_url(ProductionUrl),
    ?assertEqual(?LETS_ENCRYPT_PROD, Result).

determine_directory_from_url_binary_test() ->
    StagingUrl = <<"https://acme-staging-v02.api.letsencrypt.org/directory">>,
    Result = acme_url:determine_directory_from_url(StagingUrl),
    ?assertEqual(?LETS_ENCRYPT_STAGING, Result).

determine_directory_from_account_staging_test() ->
    Account = #acme_account{
        url = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123",
        key = test_key,
        kid = "test_kid"
    },
    Result = acme_url:determine_directory_from_account(Account),
    ?assertEqual(?LETS_ENCRYPT_STAGING, Result).

determine_directory_from_account_production_test() ->
    Account = #acme_account{
        url = "https://acme-v02.api.letsencrypt.org/acme/acct/123",
        key = test_key,
        kid = "test_kid"
    },
    Result = acme_url:determine_directory_from_account(Account),
    ?assertEqual(?LETS_ENCRYPT_PROD, Result).

%%%--------------------------------------------------------------------
%%% Header Processing Tests
%%%--------------------------------------------------------------------

headers_to_map_test() ->
    Headers = [
        {"Content-Type", "application/json"},
        {"Authorization", "Bearer token123"},
        {<<"Location">>, <<"https://example.com/resource">>}
    ],
    Result = acme_url:headers_to_map(Headers),
    Expected = #{
        <<"Content-Type">> => <<"application/json">>,
        <<"Authorization">> => <<"Bearer token123">>,
        <<"Location">> => <<"https://example.com/resource">>
    },
    ?assertEqual(Expected, Result).

headers_to_map_empty_test() ->
    Result = acme_url:headers_to_map([]),
    ?assertEqual(#{}, Result).

headers_to_map_mixed_types_test() ->
    Headers = [
        {"string-key", "string-value"},
        {<<"binary-key">>, <<"binary-value">>},
        {<<"mixed-key">>, "mixed-value"}
    ],
    Result = acme_url:headers_to_map(Headers),
    ?assertEqual(3, maps:size(Result)),
    ?assert(maps:is_key(<<"string-key">>, Result)),
    ?assert(maps:is_key(<<"binary-key">>, Result)),
    ?assert(maps:is_key(<<"mixed-key">>, Result)).

%%%--------------------------------------------------------------------
%%% URL Normalization Tests
%%%--------------------------------------------------------------------

normalize_url_with_scheme_test() ->
    Url = "https://example.com/path",
    Result = acme_url:normalize_url(Url),
    ?assertEqual("https://example.com/path", Result).

normalize_url_without_scheme_test() ->
    Url = "example.com/path",
    Result = acme_url:normalize_url(Url),
    ?assertEqual("https://example.com/path", Result).

normalize_url_http_test() ->
    Url = "http://example.com/path",
    Result = acme_url:normalize_url(Url),
    ?assertEqual("http://example.com/path", Result).

normalize_url_binary_test() ->
    Url = <<"example.com/api">>,
    Result = acme_url:normalize_url(Url),
    ?assertEqual("https://example.com/api", Result).

normalize_url_empty_test() ->
    Result = acme_url:normalize_url(""),
    ?assertEqual("https://", Result).

%%%--------------------------------------------------------------------
%%% Edge Cases and Error Handling
%%%--------------------------------------------------------------------

extract_base_url_malformed_test() ->
    % Test with malformed URLs - function returns the malformed URL as-is
    Result = acme_url:extract_base_url("://malformed"),
    ?assertEqual("://malformed", Result).

extract_host_malformed_test() ->
    % Test with malformed URLs - function extracts host portion
    Result = acme_url:extract_host_from_url("://malformed"),
    ?assertEqual(<<"malformed">>, Result).

extract_path_malformed_test() ->
    % Test with malformed URLs - function returns default path
    Result = acme_url:extract_path_from_url("://malformed"),
    ?assertEqual("/", Result).

%%%--------------------------------------------------------------------
%%% Integration Tests
%%%--------------------------------------------------------------------

url_parsing_roundtrip_test() ->
    OriginalUrl = "https://acme-v02.api.letsencrypt.org/directory",
    BaseUrl = acme_url:extract_base_url(OriginalUrl),
    Host = acme_url:extract_host_from_url(OriginalUrl),
    Path = acme_url:extract_path_from_url(OriginalUrl),

    ?assertEqual("https://acme-v02.api.letsencrypt.org", BaseUrl),
    ?assertEqual(<<"acme-v02.api.letsencrypt.org">>, Host),
    ?assertEqual("/directory", Path),

    % Reconstruct URL
    ReconstructedUrl = BaseUrl ++ Path,
    ?assertEqual(OriginalUrl, ReconstructedUrl).

%%%--------------------------------------------------------------------
%%% Test Suite
%%%--------------------------------------------------------------------

acme_url_test_() ->
    [
        {"URL parsing tests", [
            fun extract_base_url_with_scheme_test/0,
            fun extract_base_url_without_scheme_test/0,
            fun extract_base_url_http_test/0,
            fun extract_base_url_binary_test/0
        ]},
        {"Host extraction tests", [
            fun extract_host_from_url_with_scheme_test/0,
            fun extract_host_from_url_without_scheme_test/0,
            fun extract_host_from_url_binary_test/0,
            fun extract_host_from_url_port_test/0
        ]},
        {"Path extraction tests", [
            fun extract_path_from_url_with_scheme_test/0,
            fun extract_path_from_url_without_scheme_test/0,
            fun extract_path_from_url_complex_path_test/0,
            fun extract_path_from_url_root_test/0,
            fun extract_path_from_url_no_path_test/0
        ]},
        {"Directory determination tests", [
            fun determine_directory_from_url_staging_test/0,
            fun determine_directory_from_url_production_test/0,
            fun determine_directory_from_url_binary_test/0,
            fun determine_directory_from_account_staging_test/0,
            fun determine_directory_from_account_production_test/0
        ]},
        {"Header processing tests", [
            fun headers_to_map_test/0,
            fun headers_to_map_empty_test/0,
            fun headers_to_map_mixed_types_test/0
        ]},
        {"URL normalization tests", [
            fun normalize_url_with_scheme_test/0,
            fun normalize_url_without_scheme_test/0,
            fun normalize_url_http_test/0,
            fun normalize_url_binary_test/0,
            fun normalize_url_empty_test/0
        ]},
        {"Error handling tests", [
            fun extract_base_url_malformed_test/0,
            fun extract_host_malformed_test/0,
            fun extract_path_malformed_test/0
        ]},
        {"Integration tests", [
            fun url_parsing_roundtrip_test/0
        ]}
    ].
