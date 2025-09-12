%%% @doc Tests for ssl_cert_validation module.
%%%
%%% This module contains comprehensive tests for SSL certificate validation
%%% including domain validation, email validation, environment validation,
%%% and parameter validation functions.

-module(ssl_cert_validation_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/ssl_cert.hrl").

%%%--------------------------------------------------------------------
%%% Domain Validation Tests
%%%--------------------------------------------------------------------

validate_domains_valid_test() ->
    ValidDomains = ["example.com", "test.example.org", "sub.domain.net"],
    {ok, Result} = ssl_cert_validation:validate_domains(ValidDomains),
    ?assertEqual(ValidDomains, Result).

validate_domains_empty_test() ->
    {error, Reason} = ssl_cert_validation:validate_domains([]),
    ?assertEqual(<<"At least one domain must be provided">>, Reason).

validate_domains_not_found_test() ->
    {error, Reason} = ssl_cert_validation:validate_domains(not_found),
    ?assertEqual(<<"Missing domains parameter">>, Reason).

validate_domains_not_list_test() ->
    {error, Reason} = ssl_cert_validation:validate_domains(<<"not_a_list">>),
    ?assertEqual(<<"Domains must be a list">>, Reason).

validate_domains_duplicates_test() ->
    Domains = ["example.com", "test.org", "example.com"],
    {error, Reason} = ssl_cert_validation:validate_domains(Domains),
    ?assertEqual(<<"Duplicate domains are not allowed">>, Reason).

validate_domains_invalid_domain_test() ->
    Domains = ["valid.com", "invalid..domain", "another.valid.org"],
    {error, Reason} = ssl_cert_validation:validate_domains(Domains),
    ?assert(binary:match(Reason, <<"Invalid domains">>) =/= nomatch).

%%%--------------------------------------------------------------------
%%% Email Validation Tests
%%%--------------------------------------------------------------------

validate_email_valid_test() ->
    Email = "test@example.com",
    {ok, Result} = ssl_cert_validation:validate_email(Email),
    ?assertEqual(Email, Result).

validate_email_not_found_test() ->
    {error, Reason} = ssl_cert_validation:validate_email(not_found),
    ?assertEqual(<<"Missing email parameter">>, Reason).

validate_email_empty_test() ->
    {error, Reason} = ssl_cert_validation:validate_email(""),
    ?assertEqual(<<"Email address cannot be empty">>, Reason).

validate_email_invalid_format_test() ->
    InvalidEmails = [
        "invalid-email",
        "@example.com",
        "test@",
        "test..test@example.com",
        "test@example.",
        ".test@example.com"
    ],
    lists:foreach(
        fun(Email) ->
            {error, Reason} = ssl_cert_validation:validate_email(Email),
            ?assertEqual(<<"Invalid email address format">>, Reason)
        end,
        InvalidEmails
    ).

%%%--------------------------------------------------------------------
%%% Environment Validation Tests
%%%--------------------------------------------------------------------

validate_environment_staging_test() ->
    {ok, Result} = ssl_cert_validation:validate_environment(<<"staging">>),
    ?assertEqual(staging, Result).

validate_environment_production_test() ->
    {ok, Result} = ssl_cert_validation:validate_environment(<<"production">>),
    ?assertEqual(production, Result).

validate_environment_atom_test() ->
    {ok, Result1} = ssl_cert_validation:validate_environment(staging),
    ?assertEqual(staging, Result1),
    {ok, Result2} = ssl_cert_validation:validate_environment(production),
    ?assertEqual(production, Result2).

validate_environment_invalid_test() ->
    {error, Reason} = ssl_cert_validation:validate_environment(<<"invalid">>),
    ?assertEqual(<<"Environment must be 'staging' or 'production'">>, Reason).

%%%--------------------------------------------------------------------
%%% Domain Validation Helper Tests
%%%--------------------------------------------------------------------

is_valid_domain_test() ->
    ValidDomains = [
        "example.com",
        "sub.example.com",
        "test-domain.org",
        "a.b.c.d.example.net",
        "123domain.com",
        "domain123.org"
    ],
    lists:foreach(
        fun(Domain) ->
            ?assert(ssl_cert_validation:is_valid_domain(Domain))
        end,
        ValidDomains
    ).

is_valid_domain_invalid_test() ->
    InvalidDomains = [
        "",
        "domain-",
        "-domain",
        "domain..com",
        ".domain.com",
        "domain.com.",
        "domain_with_underscore.com",
        % Too long
        string:copies("a", 254) ++ ".com",
        "domain with spaces.com"
    ],
    lists:foreach(
        fun(Domain) ->
            ?assertNot(ssl_cert_validation:is_valid_domain(Domain))
        end,
        InvalidDomains
    ).

%%%--------------------------------------------------------------------
%%% Email Validation Helper Tests
%%%--------------------------------------------------------------------

is_valid_email_test() ->
    ValidEmails = [
        "test@example.com",
        "user.name@domain.org",
        "user+tag@example.net",
        "user123@test-domain.com",
        "a@b.co"
    ],
    lists:foreach(
        fun(Email) ->
            ?assert(ssl_cert_validation:is_valid_email(Email))
        end,
        ValidEmails
    ).

is_valid_email_invalid_test() ->
    InvalidEmails = [
        "",
        "invalid",
        "@example.com",
        "test@",
        "test@@example.com",
        "test@example",
        "test.@example.com",
        ".test@example.com",
        "test@.example.com",
        "test@example..com",
        "test@example.com."
    ],
    lists:foreach(
        fun(Email) ->
            ?assertNot(ssl_cert_validation:is_valid_email(Email))
        end,
        InvalidEmails
    ).

%%%--------------------------------------------------------------------
%%% Request Parameter Validation Tests
%%%--------------------------------------------------------------------

validate_request_params_valid_test() ->
    Domains = ["example.com", "test.org"],
    Email = "admin@example.com",
    Environment = <<"staging">>,
    {ok, Result} = ssl_cert_validation:validate_request_params(Domains, Email, Environment),
    Expected = #{
        domains => Domains,
        email => Email,
        environment => staging,
        key_size => ?SSL_CERT_KEY_SIZE
    },
    ?assertEqual(Expected, Result).

validate_request_params_invalid_domains_test() ->
    {error, _} = ssl_cert_validation:validate_request_params([], "test@example.com", <<"staging">>).

validate_request_params_invalid_email_test() ->
    {error, _} = ssl_cert_validation:validate_request_params(
        ["example.com"], "invalid-email", <<"staging">>
    ).

validate_request_params_invalid_environment_test() ->
    {error, _} = ssl_cert_validation:validate_request_params(
        ["example.com"], "test@example.com", <<"invalid">>
    ).

validate_request_params_exception_test() ->
    % Test with completely invalid input that would cause an exception
    {error, Reason} = ssl_cert_validation:validate_request_params(
        <<"invalid">>, <<"invalid">>, <<"invalid">>
    ),
    ?assertEqual(<<"Invalid request parameters">>, Reason).

%%%--------------------------------------------------------------------
%%% Test Suite
%%%--------------------------------------------------------------------

ssl_cert_validation_test_() ->
    [
        {"Domain validation tests", [
            fun validate_domains_valid_test/0,
            fun validate_domains_empty_test/0,
            fun validate_domains_not_found_test/0,
            fun validate_domains_not_list_test/0,
            fun validate_domains_duplicates_test/0,
            fun validate_domains_invalid_domain_test/0
        ]},
        {"Email validation tests", [
            fun validate_email_valid_test/0,
            fun validate_email_not_found_test/0,
            fun validate_email_empty_test/0,
            fun validate_email_invalid_format_test/0
        ]},
        {"Environment validation tests", [
            fun validate_environment_staging_test/0,
            fun validate_environment_production_test/0,
            fun validate_environment_atom_test/0,
            fun validate_environment_invalid_test/0
        ]},
        {"Domain helper tests", [
            fun is_valid_domain_test/0,
            fun is_valid_domain_invalid_test/0
        ]},
        {"Email helper tests", [
            fun is_valid_email_test/0,
            fun is_valid_email_invalid_test/0
        ]},
        {"Request parameter tests", [
            fun validate_request_params_valid_test/0,
            fun validate_request_params_invalid_domains_test/0,
            fun validate_request_params_invalid_email_test/0,
            fun validate_request_params_invalid_environment_test/0,
            fun validate_request_params_exception_test/0
        ]}
    ].
