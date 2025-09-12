-define(event(X),
    case os:getenv("SSL_CERT_DEBUG") of
        false -> ok;
        _ -> io:format("[~p:~p:~p] ~p~n", [?MODULE, ?FUNCTION_NAME, ?LINE, X])
    end
).

-define(event(Topic, X),
    case os:getenv("SSL_CERT_DEBUG") of
        false -> ok;
        _ -> io:format("[~p:~p:~p:~p] ~p~n", [Topic, ?MODULE, ?FUNCTION_NAME, ?LINE, X])
    end
).

-define(event(Topic, X, Opts),
    case os:getenv("SSL_CERT_DEBUG") of
        false ->
            ok;
        _ ->
            io:format("[~p:~p:~p:~p] ~p ~p~n", [
                maps:get(topic, Opts, Topic), ?MODULE, ?FUNCTION_NAME, ?LINE, X, Opts
            ])
    end
).
