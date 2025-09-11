%%% @doc SSL Certificate utility module.
%%%
%%% This module provides utility functions for SSL certificate management
%%% including error formatting, response building, and common helper functions
%%% used across the SSL certificate system.
%%%
%%% The module centralizes formatting logic and provides consistent error
%%% handling and response generation for the SSL certificate system.
-module(ssl_utils).

%% No includes needed for basic utility functions

%% Public API
-export([
    format_error_details/1,
    build_error_response/2,
    build_success_response/2,
    format_validation_error/1,
    normalize_domains/1,
    normalize_email/1,
    %% HTTP client functions
    http_post/3,
    http_get/1,
    http_head/1
]).

-export([
    bin/1,
    list/1,
    json_encode/1,
    json_decode/1,
    json_decode/2
]).

%% Type specifications
-spec format_error_details(term()) -> binary().
-spec build_error_response(integer(), binary()) -> {error, map()}.
-spec build_success_response(integer(), map()) -> {ok, map()}.
-spec format_validation_error(binary()) -> {error, map()}.
-spec normalize_domains(term()) -> [string()].
-spec normalize_email(term()) -> string().
-spec http_post(string(), [tuple()], binary()) -> {ok, integer(), [tuple()], binary()} | {error, term()}.
-spec http_get(string()) -> {ok, integer(), [tuple()], binary()} | {error, term()}.
-spec http_head(string()) -> {ok, integer(), [tuple()], binary()} | {error, term()}.

%% @doc Formats error details for user-friendly display.
%%
%% This function takes various error reason formats and converts them
%% to user-friendly binary strings suitable for API responses.
%%
%% @param ErrorReason The error reason to format
%% @returns Formatted error details as binary
format_error_details(ErrorReason) ->
    case ErrorReason of
        {http_error, StatusCode, Details} ->
            StatusBin = ssl_utils:bin(integer_to_list(StatusCode)),
            DetailsBin = case Details of
                Map when is_map(Map) ->
                    case maps:get(<<"detail">>, Map, undefined) of
                        undefined -> ssl_utils:bin(io_lib:format("~p", [Map]));
                        Detail -> Detail
                    end;
                Binary when is_binary(Binary) -> Binary;
                Other -> ssl_utils:bin(io_lib:format("~p", [Other]))
            end,
            <<"HTTP ", StatusBin/binary, ": ", DetailsBin/binary>>;
        {connection_failed, ConnReason} ->
            ConnBin = ssl_utils:bin(io_lib:format("~p", [ConnReason])),
            <<"Connection failed: ", ConnBin/binary>>;
        {validation_failed, ValidationErrors} when is_list(ValidationErrors) ->
            ErrorList = [ssl_utils:bin(io_lib:format("~s", [E])) || E <- ValidationErrors],
            ErrorsBin = ssl_utils:bin(string:join([binary_to_list(E) || E <- ErrorList], ", ")),
            <<"Validation failed: ", ErrorsBin/binary>>;
        {acme_error, AcmeDetails} ->
            AcmeBin = ssl_utils:bin(io_lib:format("~p", [AcmeDetails])),
            <<"ACME error: ", AcmeBin/binary>>;
        Binary when is_binary(Binary) ->
            Binary;
        List when is_list(List) ->
            ssl_utils:bin(List);
        Atom when is_atom(Atom) ->
            ssl_utils:bin(atom_to_list(Atom));
        Other ->
            ssl_utils:bin(io_lib:format("~p", [Other]))
    end.

%% @doc Builds a standardized error response.
%%
%% @param StatusCode HTTP status code
%% @param ErrorMessage Error message as binary
%% @returns Standardized error response tuple
build_error_response(StatusCode, ErrorMessage) when is_integer(StatusCode), is_binary(ErrorMessage) ->
    {error, #{<<"status">> => StatusCode, <<"error">> => ErrorMessage}}.

%% @doc Builds a standardized success response.
%%
%% @param StatusCode HTTP status code
%% @param Body Response body map
%% @returns Standardized success response tuple
build_success_response(StatusCode, Body) when is_integer(StatusCode), is_map(Body) ->
    {ok, #{<<"status">> => StatusCode, <<"body">> => Body}}.


%% @doc Formats validation errors for consistent API responses.
%%
%% @param ValidationError Validation error message
%% @returns Formatted validation error response
format_validation_error(ValidationError) when is_binary(ValidationError) ->
    build_error_response(400, ValidationError).

%% @doc Normalizes domain input to a list of strings.
%%
%% This function handles various input formats for domains and converts
%% them to a consistent list of strings format.
%%
%% @param Domains Domain input in various formats
%% @returns List of domain strings
normalize_domains(Domains) when is_list(Domains) ->
    try
        [ssl_utils:list(D) || D <- Domains, is_binary(D) orelse is_list(D)]
    catch
        _:_ -> []
    end;
normalize_domains(Domain) when is_binary(Domain) ->
    [ssl_utils:list(Domain)];
normalize_domains(Domain) when is_list(Domain) ->
    try
        [ssl_utils:list(Domain)]
    catch
        _:_ -> []
    end;
normalize_domains(_) ->
    [].

%% @doc Normalizes email input to a string.
%%
%% This function handles various input formats for email addresses and
%% converts them to a consistent string format.
%%
%% @param Email Email input in various formats
%% @returns Email as string
normalize_email(Email) when is_binary(Email) ->
    ssl_utils:list(Email);
normalize_email(Email) when is_list(Email) ->
    try
        ssl_utils:list(Email)
    catch
        _:_ -> ""
    end;
normalize_email(_) ->
    "".

%% @doc Makes an HTTP POST request using gun.
%%
%% @param Url The target URL (string or binary)
%% @param Headers List of header tuples
%% @param Body Request body as binary
%% @returns {ok, StatusCode, ResponseHeaders, ResponseBody} | {error, Reason}
http_post(Url, Headers, Body) ->
    UrlStr = case Url of
        U when is_binary(U) -> binary_to_list(U);
        U when is_list(U) -> U
    end,
    http_request(post, UrlStr, Headers, Body).

%% @doc Makes an HTTP GET request using gun.
%%
%% @param Url The target URL (string or binary)
%% @returns {ok, StatusCode, ResponseHeaders, ResponseBody} | {error, Reason}
http_get(Url) ->
    UrlStr = case Url of
        U when is_binary(U) -> binary_to_list(U);
        U when is_list(U) -> U
    end,
    http_request(get, UrlStr, [], <<>>).

%% @doc Makes an HTTP HEAD request using gun.
%%
%% @param Url The target URL (string or binary)
%% @returns {ok, StatusCode, ResponseHeaders, ResponseBody} | {error, Reason}  
http_head(Url) ->
    UrlStr = case Url of
        U when is_binary(U) -> binary_to_list(U);
        U when is_list(U) -> U
    end,
    http_request(head, UrlStr, [], <<>>).

%% @doc Internal function to make HTTP requests using gun.
%%
%% @param Method HTTP method (get, post, head, etc.)
%% @param Url The target URL
%% @param Headers List of header tuples
%% @param Body Request body as binary
%% @returns {ok, StatusCode, ResponseHeaders, ResponseBody} | {error, Reason}
http_request(Method, Url, Headers, Body) ->
    try
        % Parse URL components
        UriMap = uri_string:parse(Url),
        Scheme = maps:get(scheme, UriMap),
        Host = maps:get(host, UriMap),
        Port = maps:get(port, UriMap, undefined),
        Path = maps:get(path, UriMap, "/"),
        
        % Determine transport and port
        {Transport, DefaultPort} = case Scheme of
            "https" -> {tls, 443};
            "http" -> {tcp, 80};
            <<"https">> -> {tls, 443};
            <<"http">> -> {tcp, 80};
            https -> {tls, 443};
            http -> {tcp, 80}
        end,
        ActualPort = case Port of
            undefined -> DefaultPort;
            P -> P
        end,
        
        % Convert headers to gun format
        GunHeaders = maps:from_list([{list_to_binary(K), list_to_binary(V)} || {K, V} <- Headers]),
        
        % Open connection
        ConnOpts = case Transport of
            tls -> #{transport => tls, tls_opts => [{verify, verify_peer}]};
            tcp -> #{transport => tcp}
        end,
        
        case gun:open(Host, ActualPort, ConnOpts) of
            {ok, ConnPid} ->
                case gun:await_up(ConnPid, 10000) of
                    {ok, _Protocol} ->
                        % Make request
                        StreamRef = case Method of
                            get -> gun:get(ConnPid, Path, GunHeaders);
                            post -> gun:post(ConnPid, Path, GunHeaders, Body);
                            head -> gun:head(ConnPid, Path, GunHeaders);
                            _ -> gun:request(ConnPid, Method, Path, GunHeaders, Body)
                        end,
                        
                        % Wait for response
                        Result = case gun:await(ConnPid, StreamRef, 10000) of
                            {response, fin, StatusCode, ResponseHeaders} ->
                                {ok, StatusCode, ResponseHeaders, <<>>};
                            {response, nofin, StatusCode, ResponseHeaders} ->
                                case gun:await_body(ConnPid, StreamRef, 10000) of
                                    {ok, ResponseBody} ->
                                        {ok, StatusCode, ResponseHeaders, ResponseBody};
                                    {error, Reason} ->
                                        {error, {body_error, Reason}}
                                end;
                            {error, Reason} ->
                                {error, {response_error, Reason}}
                        end,
                        
                        gun:close(ConnPid),
                        Result;
                    {error, Reason} ->
                        gun:close(ConnPid),
                        {error, {connection_up_failed, Reason}}
                end;
            {error, Reason} ->
                {error, {connection_failed, Reason}}
        end
    catch
        error:Error ->
            {error, {http_request_error, Error}};
        exit:Exit ->
            {error, {http_request_exit, Exit}};
        throw:Throw ->
            {error, {http_request_throw, Throw}}
    end.

%% @doc Coerce a value to a binary.
bin(Value) when is_atom(Value) ->
    atom_to_binary(Value, utf8);
bin(Value) when is_integer(Value) ->
    integer_to_binary(Value);
bin(Value) when is_float(Value) ->
    float_to_binary(Value, [{decimals, 10}, compact]);
bin(Value) when is_list(Value) ->
    list_to_binary(Value);
bin(Value) when is_binary(Value) ->
    Value.

%% @doc Coerce a value to a string list.
list(Value) when is_binary(Value) ->
    binary_to_list(Value);
list(Value) when is_list(Value) -> Value;
list(Value) when is_atom(Value) -> atom_to_list(Value).

%% @doc Takes a term in Erlang's native form and encodes it as a JSON string.
json_encode(Term) ->
    iolist_to_binary(json:encode(Term)).

%% @doc Takes a JSON string and decodes it into an Erlang term.
json_decode(Bin) -> json:decode(Bin).
json_decode(Bin, _Opts) -> json_decode(Bin).