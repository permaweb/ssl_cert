# SSL Certificate Library

[![Hex.pm](https://img.shields.io/hexpm/v/ssl_cert.svg?maxAge=2592000?style=plastic)](https://hex.pm/packages/ssl_cert)
[![Hex.pm](https://img.shields.io/hexpm/dt/ssl_cert.svg?maxAge=2592000)](https://hex.pm/packages/ssl_cert)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/ssl_cert/)

A comprehensive SSL certificate management library with Let's Encrypt ACME v2 support for Erlang/OTP applications.

## Index

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [Dependencies](#dependencies)
- [Code Coverage](#code-coverage)
- [Development Commands](#development-commands)

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

### Device Configuration

Configure the SSL certificate device with the required options:

```erlang
%% Configuration for SSL certificate requests
Opts = #{
    <<"ssl_opts">> => #{
        <<"domains">> => [<<"example.com">>, <<"www.example.com">>],
        <<"email">> => <<"admin@example.com">>,
        <<"environment">> => <<"staging">>  % Use "production" for live certificates
    }
}.
```

### Certificate Request Workflow

#### Step 1: Request Certificate
```erlang
%% Initiate certificate request - returns DNS challenges
{ok, Response} = dev_ssl_cert:request(undefined, undefined, Opts),
#{<<"body">> := #{
    <<"challenges">> := Challenges,
    <<"message">> := <<"Create DNS TXT records for the following challenges, then call finalize">>
}} = Response.
```

#### Step 2: Set DNS TXT Records
Based on the returned challenges, create DNS TXT records:
```
_acme-challenge.example.com.     TXT "challenge_token_here"
_acme-challenge.www.example.com. TXT "challenge_token_here"
```

#### Step 3: Finalize Certificate
```erlang
%% After DNS records are set, finalize the certificate
{ok, FinalResponse} = dev_ssl_cert:finalize(undefined, undefined, Opts),
#{<<"body">> := #{
    <<"certificate_pem">> := CertPem,
    <<"key_pem">> := KeyPem,
    <<"domains">> := Domains
}} = FinalResponse.
```

### Certificate Management

#### Renew Certificate
```erlang
%% Renew existing certificate
RenewOpts = #{
    <<"ssl_opts">> => #{
        <<"domains">> => [<<"example.com">>, <<"www.example.com">>],
        <<"email">> => <<"admin@example.com">>,
        <<"environment">> => <<"production">>
    }
},
{ok, RenewResponse} = dev_ssl_cert:renew(undefined, undefined, RenewOpts).
```

#### Delete Certificate
```erlang
%% Delete stored certificate
DeleteOpts = #{
    <<"ssl_opts">> => #{
        <<"domains">> => [<<"example.com">>, <<"www.example.com">>]
    }
},
{ok, DeleteResponse} = dev_ssl_cert:delete(undefined, undefined, DeleteOpts).
```

### Environment Configuration

#### Staging Environment (for testing)
```erlang
StagingOpts = #{
    <<"ssl_opts">> => #{
        <<"domains">> => [<<"test.example.com">>],
        <<"email">> => <<"test@example.com">>,
        <<"environment">> => <<"staging">>
    }
}.
```

#### Production Environment
```erlang
ProductionOpts = #{
    <<"ssl_opts">> => #{
        <<"domains">> => [<<"example.com">>],
        <<"email">> => <<"admin@example.com">>,
        <<"environment">> => <<"production">>
    }
}.
```

### Direct Module Usage

For advanced use cases, you can call the underlying modules directly:

```erlang
%% Validate request parameters
{ok, ValidatedParams} = ssl_cert_validation:validate_request_params(
    [<<"example.com">>], <<"admin@example.com">>, <<"staging">>),

%% Process certificate request
{ok, ProcessResponse} = ssl_cert_ops:process_certificate_request(ValidatedParams, Wallet),

%% Validate DNS challenges
{ok, ValidationResponse} = ssl_cert_challenge:validate_dns_challenges_state(RequestState, PrivateKey),

%% Generate CSR
{ok, {CsrDer, PrivateKey}} = acme_csr:generate_csr([<<"example.com">>], #{}).
```

## Modules

- **`acme_client`** - Main ACME client API
- **`ssl_cert_ops`** - High-level certificate operations
- **`acme_protocol`** - Core ACME protocol implementation
- **`acme_crypto`** - Cryptographic operations and JWS
- **`acme_csr`** - Certificate Signing Request generation
- **`ssl_cert_challenge`** - Challenge handling and validation
- **`ssl_cert_validation`** - Certificate validation utilities
- **`ssl_cert_state`** - State management utilities
- **`ssl_utils`** - Utility functions and HTTP client

## Dependencies

- `gun` - Modern HTTP/2 client for ACME communication
- `crypto` - Cryptographic operations
- `public_key` - Public key operations
- `ssl` - SSL/TLS support
- `inets` - Additional HTTP utilities

## Code Coverage

Current test coverage across all modules:

| Module | Coverage |
|--------|----------|
| **Core Modules** | |
| `acme_client` | 25% |
| `acme_crypto` | 65% |
| `acme_csr` | 81% |
| `acme_http` | 49% |
| `acme_protocol` | 26% |
| `acme_url` | 100% |
| `ssl_cert_challenge` | 18% |
| `ssl_cert_ops` | 24% |
| `ssl_cert_state` | 65% |
| `ssl_cert_validation` | 95% |
| `ssl_utils` | 29% |
| **Test Modules** | |
| `acme_client_tests` | 91% |
| `acme_crypto_tests` | 100% |
| `acme_csr_tests` | 91% |
| `acme_http_tests` | 100% |
| `acme_protocol_tests` | 91% |
| `acme_url_tests` | 100% |
| `ssl_cert_challenge_tests` | 100% |
| `ssl_cert_integration_tests` | 100% |
| `ssl_cert_ops_tests` | 100% |
| `ssl_cert_state_tests` | 100% |
| `ssl_cert_test_suite` | 10% |
| `ssl_cert_validation_tests` | 100% |
| `ssl_utils_tests` | 100% |
| **Total Coverage** | **68%** |

### Coverage Analysis

- **High Coverage (80%+)**: `acme_csr`, `acme_url`, `ssl_cert_validation`
- **Medium Coverage (50-79%)**: `acme_crypto`, `ssl_cert_state`
- **Low Coverage (<50%)**: `acme_client`, `acme_http`, `acme_protocol`, `ssl_cert_challenge`, `ssl_cert_ops`, `ssl_utils`

## Development Commands

### Code Quality and Formatting
```bash
# Format all Erlang files
rebar3 fmt

# Check if files need formatting (don't modify)
rebar3 fmt --check

# Run linter to check code quality
rebar3 lint
```

### Testing
```bash
# Compile and run all tests
rebar3 as test eunit

# Run specific test module
rebar3 as test eunit --module=my_module_tests
```

### Code Coverage
```bash
# Run tests with coverage analysis
rebar3 cover

# Generate coverage reports
rebar3 covertool generate

# Full test and coverage workflow
rebar3 as test eunit && rebar3 cover && rebar3 covertool generate
```

### Documentation and Publishing
```bash
# Generate HTML documentation
rebar3 ex_doc

# Authenticate with Hex (one-time setup)
rebar3 hex user auth

# Publish to Hex
rebar3 hex publish
```

### Development Workflow
```bash
# Complete quality check before commit
rebar3 clean
rebar3 fmt --check
rebar3 lint
rebar3 as test compile
rebar3 as test eunit
rebar3 cover
rebar3 covertool generate
```