# SSL Certificate Library

A comprehensive SSL certificate management library with Let's Encrypt ACME v2 support for Erlang/OTP applications.

## Features

- Full ACME v2 protocol support
- Let's Encrypt certificate automation  
- DNS and HTTP-01 challenge support
- Certificate lifecycle management
- Cryptographic operations for certificate handling
- Comprehensive validation and state management
- Modern HTTP/2 client using gun

## Installation

Add this library to your `rebar.config` dependencies:

```erlang
{deps, [
    {ssl_cert, {git, "https://github.com/permaweb/ssl_cert.git", {branch, "main"}}}
]}.
```

## Usage

### Basic Certificate Request

```erlang
%% Start the application dependencies
application:ensure_all_started(ssl_cert).

%% Create ACME account
Config = #{
    directory_url => "https://acme-staging-v02.api.letsencrypt.org/directory",
    contact => ["mailto:admin@example.com"]
},
{ok, Account} = acme_client:create_account(Config, #{}),

%% Request certificate for domains
Domains = ["example.com", "www.example.com"],
{ok, Order} = acme_client:request_certificate(Account, Domains),

%% Get DNS challenge for validation
{ok, Challenge} = acme_client:get_dns_challenge(Account, Order),

%% After setting up DNS records, validate the challenge
{ok, _} = acme_client:validate_challenge(Account, Challenge),

%% Finalize order with CSR
{ok, Csr} = acme_csr:generate_csr(Domains, #{}),
{ok, FinalOrder} = acme_client:finalize_order(Account, Order, Csr),

%% Download the certificate
{ok, Certificate} = acme_client:download_certificate(Account, FinalOrder).
```

### Certificate Operations

```erlang
%% Process certificate request with full lifecycle
RequestState = #{
    account => Account,
    order => Order,
    domains => Domains
},
{ok, CertData} = ssl_cert_ops:process_certificate_request(RequestState, #{}),

%% Renew existing certificate
{ok, RenewedCert} = ssl_cert_ops:renew_certificate(Domains, #{account => Account}),

%% Delete certificate
{ok, _} = ssl_cert_ops:delete_certificate(Domains, #{}).
```

## Main Modules

- **`acme_client`** - Main ACME client API
- **`ssl_cert_ops`** - High-level certificate operations
- **`acme_protocol`** - Core ACME protocol implementation
- **`acme_crypto`** - Cryptographic operations and JWS
- **`acme_csr`** - Certificate Signing Request generation
- **`ssl_cert_challenge`** - Challenge handling and validation
- **`ssl_cert_validation`** - Certificate validation utilities
- **`ssl_cert_state`** - State management utilities
- **`ssl_utils`** - Utility functions and HTTP client

## Configuration

The library supports both Let's Encrypt staging and production environments:

```erlang
%% Staging (for testing)
StagingConfig = #{
    directory_url => "https://acme-staging-v02.api.letsencrypt.org/directory"
},

%% Production
ProductionConfig = #{
    directory_url => "https://acme-v02.api.letsencrypt.org/directory"
}.
```

## Dependencies

- `gun` - Modern HTTP/2 client for ACME communication
- `crypto` - Cryptographic operations
- `public_key` - Public key operations
- `ssl` - SSL/TLS support
- `inets` - Additional HTTP utilities
