-module(acme_client).
-moduledoc """
ACME client module for Let's Encrypt certificate management.

This module provides the main API for ACME (Automatic Certificate Management
Environment) v2 protocol operations. It serves as a facade that orchestrates
calls to specialized modules for HTTP communication, cryptographic operations,
CSR generation, and protocol implementation.

The module supports both staging and production Let's Encrypt environments
and provides comprehensive logging through HyperBEAM's event system.

This refactored version delegates complex operations to specialized modules:
- acme_protocol: Core ACME protocol operations
- acme_http: HTTP client and communication
- acme_crypto: Cryptographic operations and JWS
- acme_csr: Certificate Signing Request generation
- acme_url: URL parsing and manipulation utilities
""".

-include("../include/ssl_cert.hrl").

%% Main ACME API
-export([
    create_account/2,
    request_certificate/2,
    get_dns_challenge/2,
    validate_challenge/2,
    get_challenge_status/2,
    finalize_order/3,
    download_certificate/2,
    get_order/2
]).

%% Utility exports for backward compatibility
-export([
    base64url_encode/1,
    get_nonce/0,
    get_fresh_nonce/1,
    determine_directory_from_url/1,
    extract_host_from_url/1,
    extract_base_url/1,
    extract_path_from_url/1,
    make_jws_post_as_get_request/3
]).

-doc """
Creates a new ACME account with Let's Encrypt.
""".
-spec create_account(map(), map()) -> {ok, acme_account()} | {error, term()}.
create_account(Config, Wallet) ->
    acme_protocol:create_account(Config, Wallet).

-doc """
Requests a certificate for the specified domains.
""".
-spec request_certificate(acme_account(), [string()]) -> {ok, acme_order()} | {error, term()}.
request_certificate(Account, Domains) ->
    acme_protocol:request_certificate(Account, Domains).

-doc """
Retrieves DNS-01 challenges for all domains in an order.
""".
-spec get_dns_challenge(acme_account(), acme_order()) -> {ok, [dns_challenge()]} | {error, term()}.
get_dns_challenge(Account, Order) ->
    acme_protocol:get_dns_challenge(Account, Order).

-doc """
Validates a DNS challenge with the ACME server.
""".
-spec validate_challenge(acme_account(), dns_challenge()) -> {ok, string()} | {error, term()}.
validate_challenge(Account, Challenge) ->
    acme_protocol:validate_challenge(Account, Challenge).

-doc """
Retrieves current challenge status using POST-as-GET.
""".
-spec get_challenge_status(acme_account(), dns_challenge()) -> {ok, string()} | {error, term()}.
get_challenge_status(Account, Challenge) ->
    acme_protocol:get_challenge_status(Account, Challenge).

-doc """
Finalizes a certificate order after all challenges are validated.
""".
-spec finalize_order(acme_account(), acme_order(), public_key:private_key()) ->
    {ok, acme_order(), public_key:private_key()} | {error, term()}.
finalize_order(Account, Order, RSAPrivKey) ->
    acme_protocol:finalize_order(Account, Order, RSAPrivKey).

-doc """
Downloads the certificate from the ACME server.
""".
-spec download_certificate(acme_account(), acme_order()) -> {ok, string()} | {error, term()}.
download_certificate(Account, Order) ->
    acme_protocol:download_certificate(Account, Order).

-doc """
Fetches the latest state of an order (POST-as-GET).
""".
-spec get_order(acme_account(), string()) -> {ok, map()} | {error, term()}.
get_order(Account, OrderUrl) ->
    acme_protocol:get_order(Account, OrderUrl).

%%%--------------------------------------------------------------------
%%% Utility Functions for Backward Compatibility
%%%--------------------------------------------------------------------

-doc """
Encodes data using base64url encoding.
""".
-spec base64url_encode(binary() | string()) -> string().
base64url_encode(Data) ->
    acme_crypto:base64url_encode(Data).

-doc """
Generates a random nonce for JWS requests (fallback).
""".
-spec get_nonce() -> string().
get_nonce() ->
    acme_http:get_nonce().

-doc """
Gets a fresh nonce from the ACME server.
""".
-spec get_fresh_nonce(string()) -> string().
get_fresh_nonce(DirectoryUrl) ->
    acme_http:get_fresh_nonce(DirectoryUrl).

-doc """
Determines the ACME directory URL from any ACME endpoint URL.
""".
-spec determine_directory_from_url(string()) -> string().
determine_directory_from_url(Url) ->
    acme_url:determine_directory_from_url(Url).

-doc """
Extracts the host from a URL.
""".
-spec extract_host_from_url(string()) -> binary().
extract_host_from_url(Url) ->
    acme_url:extract_host_from_url(Url).

-doc """
Extracts the base URL (scheme + host) from a complete URL.
""".
-spec extract_base_url(string()) -> string().
extract_base_url(Url) ->
    acme_url:extract_base_url(Url).

-doc """
Extracts the path from a URL.
""".
-spec extract_path_from_url(string()) -> string().
extract_path_from_url(Url) ->
    acme_url:extract_path_from_url(Url).

-doc """
Creates and sends a JWS POST-as-GET request.
""".
-spec make_jws_post_as_get_request(string(), public_key:private_key(), string()) ->
    {ok, map(), term()} | {error, term()}.
make_jws_post_as_get_request(Url, PrivateKey, Kid) ->
    acme_http:make_jws_post_as_get_request(Url, PrivateKey, Kid).
