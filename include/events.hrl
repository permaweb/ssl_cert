
-define(event(X), io:format("[~p:~p:~p] ~p~n", [?MODULE, ?FUNCTION_NAME, ?LINE, X])).
-define(event(Topic, X), io:format("[~p:~p:~p:~p] ~p~n", [Topic, ?MODULE, ?FUNCTION_NAME, ?LINE, X])).
-define(event(Topic, X, Opts), io:format("[~p:~p:~p:~p] ~p ~p~n", [maps:get(topic, Opts, Topic), ?MODULE, ?FUNCTION_NAME, ?LINE, X, Opts])).
