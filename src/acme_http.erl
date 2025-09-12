-module(acme_http).
-moduledoc """
ACME HTTP client module.

This module provides HTTP client functionality specifically designed for
ACME (Automatic Certificate Management Environment) protocol communication.
It handles JWS (JSON Web Signature) requests, nonce management, error handling,
and response processing required for secure communication with ACME servers.
""".

-include("../include/events.hrl").

%% Public API
-export([
    make_jws_request/4,
    make_jws_post_as_get_request/3,
    make_get_request/1,
    get_fresh_nonce/1,
    get_nonce/0,
    get_directory/1,
    extract_location_header/1,
    extract_nonce_header/1,
    process_http_response/3,
    fallback_random_nonce/0,
    make_acme_post_request/2
]).

%% Type specifications
-spec make_jws_request(string(), map(), public_key:private_key(), string() | undefined) ->
    {ok, map(), term()} | {error, term()}.
-spec make_jws_post_as_get_request(string(), public_key:private_key(), string()) ->
    {ok, map(), term()} | {error, term()}.
-spec make_get_request(string()) -> {ok, binary()} | {error, term()}.
-spec get_fresh_nonce(string()) -> string().
-spec get_nonce() -> string().
-spec get_directory(string()) -> map().
-spec extract_location_header(term()) -> string() | undefined.
-spec extract_nonce_header(term()) -> string() | undefined.
-spec process_http_response(integer(), term(), binary()) -> {ok, map(), term()} | {error, term()}.
-spec fallback_random_nonce() -> string().
-spec make_acme_post_request(string(), binary()) ->
    {ok, integer(), term(), binary()} | {error, term()}.
-spec find_header_case_insensitive(string(), term()) -> string() | undefined.

-doc """
Creates and sends a JWS-signed request to the ACME server.

This function creates a complete JWS (JSON Web Signature) request according
to the ACME v2 protocol specification. It handles nonce retrieval, header
creation, payload signing, and HTTP communication with comprehensive error
handling and logging.

@param Url The target URL
@param Payload The request payload map
@param PrivateKey The account's private key
@param Kid The account's key identifier (undefined for new accounts)
@returns {ok, Response, Headers} on success, {error, Reason} on failure
""".
make_jws_request(Url, Payload, PrivateKey, Kid) ->
    try
        % Get fresh nonce from ACME server
        DirectoryUrl = acme_url:determine_directory_from_url(Url),
        FreshNonce = get_fresh_nonce(DirectoryUrl),
        % Create JWS header
        Header = acme_crypto:create_jws_header(Url, PrivateKey, Kid, FreshNonce),
        % Encode components
        HeaderB64 = acme_crypto:base64url_encode(ssl_utils:json_encode(Header)),
        PayloadB64 = acme_crypto:base64url_encode(ssl_utils:json_encode(Payload)),
        % Create signature
        SignatureB64 = acme_crypto:create_jws_signature(HeaderB64, PayloadB64, PrivateKey),
        % Create JWS
        Jws = #{
            <<"protected">> => ssl_utils:bin(HeaderB64),
            <<"payload">> => ssl_utils:bin(PayloadB64),
            <<"signature">> => ssl_utils:bin(SignatureB64)
        },
        % Make HTTP request
        Body = ssl_utils:json_encode(Jws),
        case make_acme_post_request(Url, Body) of
            {ok, StatusCode, ResponseHeaders, ResponseBody} ->
                process_http_response(StatusCode, ResponseHeaders, ResponseBody);
            {error, Reason} ->
                {error, {connection_failed, Reason}}
        end
    catch
        Error:JwsReason:Stacktrace ->
            ?event(acme, {acme_jws_request_error, Url, Error, JwsReason, Stacktrace}),
            {error, {jws_request_failed, Error, JwsReason}}
    end.

-doc """
Creates and sends a JWS POST-as-GET (empty payload) request per ACME spec.

Some ACME resources require POST-as-GET with an empty payload according to
RFC 8555. This function creates such requests with proper JWS signing
but an empty payload string.

@param Url Target URL
@param PrivateKey Account private key
@param Kid Account key identifier (KID)
@returns {ok, Response, Headers} or {error, Reason}
""".
make_jws_post_as_get_request(Url, PrivateKey, Kid) ->
    try
        DirectoryUrl = acme_url:determine_directory_from_url(Url),
        FreshNonce = get_fresh_nonce(DirectoryUrl),
        Header = acme_crypto:create_jws_header(Url, PrivateKey, Kid, FreshNonce),
        HeaderB64 = acme_crypto:base64url_encode(ssl_utils:json_encode(Header)),
        % Per RFC8555 POST-as-GET uses an empty payload
        PayloadB64 = "",
        SignatureB64 = acme_crypto:create_jws_signature(HeaderB64, PayloadB64, PrivateKey),
        Jws = #{
            <<"protected">> => ssl_utils:bin(HeaderB64),
            <<"payload">> => ssl_utils:bin(PayloadB64),
            <<"signature">> => ssl_utils:bin(SignatureB64)
        },
        Body = ssl_utils:json_encode(Jws),
        case make_acme_post_request(Url, Body) of
            {ok, StatusCode, ResponseHeaders, ResponseBody} ->
                process_http_response(StatusCode, ResponseHeaders, ResponseBody);
            {error, Reason} ->
                {error, {connection_failed, Reason}}
        end
    catch
        Error:JwsReason:Stacktrace ->
            ?event(acme, {acme_jws_post_as_get_error, Url, Error, JwsReason, Stacktrace}),
            {error, {jws_request_failed, Error, JwsReason}}
    end.

-doc """
Makes a GET request to the specified URL.

This function performs a simple HTTP GET request with appropriate
user agent headers and error handling for ACME protocol communication.

@param Url The target URL
@returns {ok, ResponseBody} on success, {error, Reason} on failure
""".
make_get_request(Url) ->
    case ssl_utils:http_get(Url) of
        {ok, StatusCode, ResponseHeaders, ResponseBody} ->
            ?event(acme, {
                acme_get_response_received,
                {status_code, StatusCode},
                {body_size, byte_size(ResponseBody)},
                {url, Url}
            }),
            case StatusCode of
                Code when Code >= 200, Code < 300 ->
                    ?event(acme, {acme_get_request_successful, {url, Url}}),
                    {ok, ResponseBody};
                _ ->
                    % Enhanced error reporting for GET failures
                    ErrorBody =
                        case ResponseBody of
                            <<>> -> <<"Empty response">>;
                            _ -> ResponseBody
                        end,
                    ?event(acme, {
                        acme_get_error_detailed,
                        {status_code, StatusCode},
                        {error_body, ErrorBody},
                        {url, Url},
                        {headers, ResponseHeaders}
                    }),
                    {error, {http_get_error, StatusCode, ErrorBody}}
            end;
        {error, Reason} ->
            ?event(acme, {
                acme_get_request_failed,
                {error_type, connection_failed},
                {reason, Reason},
                {url, Url}
            }),
            {error, {connection_failed, Reason}}
    end.

-doc """
Gets a fresh nonce from the ACME server.

This function retrieves a fresh nonce from Let's Encrypt's newNonce
endpoint as required by the ACME v2 protocol. Each JWS request must
use a unique nonce to prevent replay attacks. It includes fallback
to random nonces if the server is unreachable.

@param DirectoryUrl The ACME directory URL to get newNonce endpoint
@returns A base64url-encoded nonce string
""".
get_fresh_nonce(DirectoryUrl) ->
    try
        Directory = get_directory(DirectoryUrl),
        NewNonceUrl = ssl_utils:list(maps:get(<<"newNonce">>, Directory)),
        ?event(acme, {acme_getting_fresh_nonce, NewNonceUrl}),
        case ssl_utils:http_head(NewNonceUrl) of
            {ok, StatusCode, ResponseHeaders, _ResponseBody} when
                StatusCode >= 200, StatusCode < 300
            ->
                ?event(acme, {
                    acme_nonce_response_received,
                    {status_code, StatusCode}
                }),
                case extract_nonce_header(ResponseHeaders) of
                    undefined ->
                        ?event(acme, {
                            acme_nonce_not_found_in_headers,
                            {available_headers,
                                case ResponseHeaders of
                                    H when is_map(H) -> maps:keys(H);
                                    H when is_list(H) -> [K || {K, _V} <- H];
                                    _ -> []
                                end},
                            {url, NewNonceUrl}
                        }),
                        % Fallback to random nonce
                        RandomNonce = acme_crypto:base64url_encode(crypto:strong_rand_bytes(16)),
                        ?event({acme_using_fallback_nonce, {nonce_length, length(RandomNonce)}}),
                        RandomNonce;
                    ExtractedNonce ->
                        NonceStr = ssl_utils:list(ExtractedNonce),
                        ?event(acme, {
                            acme_fresh_nonce_received,
                            {nonce, NonceStr},
                            {nonce_length, length(NonceStr)},
                            {url, NewNonceUrl}
                        }),
                        NonceStr
                end;
            {ok, StatusCode, ResponseHeaders, ResponseBody} ->
                ?event(acme, {
                    acme_nonce_request_failed_with_response,
                    {status_code, StatusCode},
                    {body, ResponseBody},
                    {headers, ResponseHeaders}
                }),
                % Fallback to random nonce
                fallback_random_nonce();
            {error, Reason} ->
                ?event(acme, {
                    acme_nonce_request_failed,
                    {reason, Reason},
                    {url, NewNonceUrl},
                    {directory_url, DirectoryUrl}
                }),
                % Fallback to random nonce
                fallback_random_nonce()
        end
    catch
        _:_ ->
            ?event(acme, {acme_nonce_fallback_to_random}),
            acme_crypto:base64url_encode(crypto:strong_rand_bytes(16))
    end.

-doc """
Generates a random nonce for JWS requests (fallback).

This function provides a fallback nonce generation mechanism when
the ACME server's newNonce endpoint is unavailable.

@returns A base64url-encoded nonce string
""".
get_nonce() ->
    acme_crypto:base64url_encode(crypto:strong_rand_bytes(16)).

-doc """
Retrieves the ACME directory from the specified URL.

This function fetches and parses the ACME directory document which
contains the URLs for various ACME endpoints (newAccount, newOrder, etc.).

@param DirectoryUrl The ACME directory URL
@returns A map containing the directory endpoints
@raises {directory_fetch_failed, Reason} if the directory cannot be retrieved
""".
get_directory(DirectoryUrl) ->
    ?event({acme_fetching_directory, DirectoryUrl}),
    case make_get_request(DirectoryUrl) of
        {ok, Response} ->
            ssl_utils:json_decode(Response);
        {error, Reason} ->
            ?event({acme_directory_fetch_failed, DirectoryUrl, Reason}),
            error({directory_fetch_failed, Reason})
    end.

-doc """
Extracts the location header from HTTP response headers.

This function handles both map and proplist header formats and
extracts the Location header value, which is used for account
and order URLs in ACME responses.

@param Headers The HTTP response headers
@returns The location header value as string, or undefined if not found
""".
extract_location_header(Headers) ->
    case Headers of
        H when is_map(H) ->
            extract_location_from_map(H);
        H when is_list(H) ->
            % Headers are in proplist format - try case insensitive lookup
            case find_header_case_insensitive("location", H) of
                undefined -> undefined;
                Value -> ssl_utils:list(Value)
            end;
        _ ->
            undefined
    end.

%%%--------------------------------------------------------------------
%%% Helper Functions for Header Extraction
%%%--------------------------------------------------------------------

-doc """
Extracts location header from map format headers.

@param HeaderMap The headers in map format
@returns The location header value as string, or undefined if not found
""".
extract_location_from_map(HeaderMap) ->
    LocationKeys = [<<"location">>, "location", <<"Location">>, "Location"],
    extract_header_from_map(HeaderMap, LocationKeys).

-doc """
Generic helper to extract a header from a map using multiple key variations.

@param HeaderMap The headers in map format
@param Keys List of possible header keys to try
@returns The header value as string, or undefined if not found
""".
extract_header_from_map(_HeaderMap, []) ->
    undefined;
extract_header_from_map(HeaderMap, [Key | Rest]) ->
    case maps:get(Key, HeaderMap, undefined) of
        undefined ->
            extract_header_from_map(HeaderMap, Rest);
        Value ->
            ssl_utils:list(Value)
    end.

-doc """
Extracts nonce header from map format headers.

@param HeaderMap The headers in map format
@returns The nonce header value as string, or undefined if not found
""".
extract_nonce_from_map(HeaderMap) ->
    NonceKeys = [<<"replay-nonce">>, "replay-nonce", <<"Replay-Nonce">>, "Replay-Nonce"],
    extract_header_from_map(HeaderMap, NonceKeys).

-doc """
Extracts the replay-nonce header from HTTP response headers.

This function handles both map and proplist header formats and
extracts the replay-nonce header value used for ACME nonce management.

@param Headers The HTTP response headers
@returns The nonce header value as string, or undefined if not found
""".
extract_nonce_header(Headers) ->
    case Headers of
        H when is_map(H) ->
            extract_nonce_from_map(H);
        H when is_list(H) ->
            % Headers are in proplist format - try case insensitive lookup
            case find_header_case_insensitive("replay-nonce", H) of
                undefined -> undefined;
                Value -> ssl_utils:list(Value)
            end;
        _ ->
            undefined
    end.

%%%--------------------------------------------------------------------
%%% Internal Helper Functions
%%%--------------------------------------------------------------------

-doc """
Processes HTTP response based on status code and content.

@param StatusCode The HTTP status code
@param ResponseHeaders The response headers
@param ResponseBody The response body
@returns {ok, Response, Headers} or {error, ErrorInfo}
""".
process_http_response(StatusCode, ResponseHeaders, ResponseBody) ->
    case StatusCode of
        Code when Code >= 200, Code < 300 ->
            Response =
                case ResponseBody of
                    <<>> ->
                        #{};
                    _ ->
                        try
                            ssl_utils:json_decode(ResponseBody)
                        catch
                            JsonError:JsonReason ->
                                ?event(acme, {
                                    acme_json_decode_failed,
                                    {error, JsonError},
                                    {reason, JsonReason},
                                    {body, ResponseBody}
                                }),
                                #{}
                        end
                end,
            ?event(acme, {acme_http_request_successful, {response_keys, maps:keys(Response)}}),
            {ok, Response, ResponseHeaders};
        _ ->
            % Enhanced error reporting for HTTP failures
            ErrorDetails =
                try
                    case ResponseBody of
                        <<>> ->
                            #{<<"error">> => <<"Empty response body">>};
                        _ ->
                            ssl_utils:json_decode(ResponseBody)
                    end
                catch
                    _:_ ->
                        #{<<"error">> => ResponseBody}
                end,
            ?event(acme, {
                acme_http_error_detailed,
                {status_code, StatusCode},
                {error_details, ErrorDetails},
                {headers, ResponseHeaders}
            }),
            {error, {http_error, StatusCode, ErrorDetails}}
    end.

-doc """
Generates a fallback random nonce with logging.

@returns A base64url-encoded random nonce
""".
fallback_random_nonce() ->
    RandomNonce = acme_crypto:base64url_encode(crypto:strong_rand_bytes(16)),
    ?event(acme, {acme_using_fallback_nonce_after_error, {nonce_length, length(RandomNonce)}}),
    RandomNonce.

%%%--------------------------------------------------------------------
%%% Internal Functions
%%%--------------------------------------------------------------------

-doc """
Makes an ACME POST request with standard headers and logging.

@param Url The URL to POST to
@param Body The request body
@returns {ok, StatusCode, Headers, Body} or {error, Reason}
""".
make_acme_post_request(Url, Body) ->
    Headers = [
        {"Content-Type", "application/jose+json"},
        {"User-Agent", "HyperBEAM-ACME-Client/1.0"}
    ],
    case ssl_utils:http_post(Url, Headers, Body) of
        {ok, StatusCode, ResponseHeaders, ResponseBody} ->
            ?event(acme, {
                acme_http_response_received,
                {status_code, StatusCode},
                {body_size, byte_size(ResponseBody)}
            }),
            {ok, StatusCode, ResponseHeaders, ResponseBody};
        {error, Reason} ->
            ?event(acme, {
                acme_http_request_failed,
                {error_type, connection_failed},
                {reason, Reason},
                {url, Url}
            }),
            {error, {connection_failed, Reason}}
    end.

-doc """
Finds a header value by name in a case-insensitive manner.

@param HeaderName The header name to find
@param Headers The headers proplist
@returns The header value or undefined
""".
find_header_case_insensitive(HeaderName, Headers) ->
    LowerName = string:lowercase(HeaderName),
    find_header_case_insensitive_helper(LowerName, Headers).

find_header_case_insensitive_helper(_LowerName, []) ->
    undefined;
find_header_case_insensitive_helper(LowerName, [{Key, Value} | Rest]) ->
    case string:lowercase(ssl_utils:list(Key)) of
        LowerName -> Value;
        _ -> find_header_case_insensitive_helper(LowerName, Rest)
    end;
find_header_case_insensitive_helper(LowerName, [_ | Rest]) ->
    find_header_case_insensitive_helper(LowerName, Rest).
