%%% @doc Shared record definitions and constants for SSL certificate management.
%%%
%%% This header file contains all the common record definitions, type specifications,
%%% and constants used by the SSL certificate management modules including the
%%% device interface, ACME client, validation, and state management modules.

%% ACME server URLs
-define(LETS_ENCRYPT_STAGING,
    "https://acme-staging-v02.api.letsencrypt.org/directory"
).
-define(LETS_ENCRYPT_PROD,
    "https://acme-v02.api.letsencrypt.org/directory"
).

%% Challenge validation polling configuration
-define(CHALLENGE_POLL_DELAY_SECONDS, 5).
-define(CHALLENGE_DEFAULT_TIMEOUT_SECONDS, 300).

%% Request defaults
-define(SSL_CERT_KEY_SIZE, 4096).
-define(SSL_CERT_STORAGE_PATH, "certificates").

%% Order polling after finalization
-define(ORDER_POLL_DELAY_SECONDS, 5).
-define(ORDER_POLL_TIMEOUT_SECONDS, 60).

%% ACME challenge status constants
-define(ACME_STATUS_VALID, <<"valid">>).
-define(ACME_STATUS_INVALID, <<"invalid">>).
-define(ACME_STATUS_PENDING, <<"pending">>).
-define(ACME_STATUS_PROCESSING, <<"processing">>).

%% ACME Account Record
%% Represents an ACME account with Let's Encrypt
-record(acme_account, {
    % Private key for account
    key :: public_key:private_key(),
    % Account URL from ACME server
    url :: string(),
    % Key ID for account
    kid :: string()
}).

%% ACME Order Record
%% Represents a certificate order with Let's Encrypt
-record(acme_order, {
    % Order URL
    url :: string(),
    % Order status (pending, valid, invalid, etc.)
    status :: string(),
    % Expiration timestamp
    expires :: string(),
    % List of domain identifiers
    identifiers :: list(),
    % List of authorization URLs
    authorizations :: list(),
    % Finalization URL
    finalize :: string(),
    % Certificate download URL (when ready)
    certificate :: string()
}).

%% DNS Challenge Record
%% Represents a DNS-01 challenge for domain validation
-record(dns_challenge, {
    % Domain name being validated
    domain :: string(),
    % Challenge token
    token :: string(),
    % Key authorization string
    key_authorization :: string(),
    % DNS TXT record value to set
    dns_value :: string(),
    % Challenge URL for validation
    url :: string()
}).

%% Type definitions for better documentation and dialyzer support
-doc "ACME account record containing private key, URL, and key ID.".
-type acme_account() :: #acme_account{}.
-doc "ACME order record containing order details and status.".
-type acme_order() :: #acme_order{}.
-doc "DNS challenge record for domain validation.".
-type dns_challenge() :: #dns_challenge{}.
-doc "ACME environment type - staging or production.".
-type acme_environment() :: staging | production.
-doc "List of domain names as strings.".
-type domain_list() :: [string()].
-doc "Email address as a string.".
-type email_address() :: string().
-doc "Validation result map with binary keys and values.".
-type validation_result() :: #{binary() => binary()}.
-doc "Request state map with binary keys and arbitrary values.".
-type request_state() :: #{binary() => term()}.

%% Export types for use in other modules
-export_type([
    acme_account/0,
    acme_order/0,
    dns_challenge/0,
    acme_environment/0,
    domain_list/0,
    email_address/0,
    validation_result/0,
    request_state/0
]).
