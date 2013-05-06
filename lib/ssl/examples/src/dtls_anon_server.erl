-module(dtls_anon_server).
-compile([export_all]).

%%-include_lib("ssl/include/ssl_srp.hrl").

main() ->
    application:start(crypto),
    application:start(public_key),
    application:start(ssl),

    {ok, ListenSocket} = ssl:listen(4433, mk_opts("server")),
    io:format("ready to accept connections at port 4433 ~p\n", [ListenSocket]),
    udp_server_loop(ListenSocket).

user_lookup(srp, Username, _UserState) ->
    Salt = ssl:random_bytes(16),
    UserPassHash = crypto:sha([Salt, crypto:sha([Username, <<$:>>, <<"secret">>])]),
    {ok, {srp_1024, Salt, UserPassHash}};

user_lookup(psk, _Username, UserState) ->
    {ok, UserState}.

renegotiate(Socket, Data) ->
    io:format("Renegotiating ~n", []),
    Result = ssl:renegotiate(Socket),
    io:format("Result ~p~n", [Result]),
    Result = ok,
    ssl:send(Socket, Data),
    case Result of
	ok ->
	    ok;
	Other ->
	    Other
    end.

mk_opts(Role) ->
    Dir = filename:join([code:lib_dir(ssl), "examples", "certs", "etc"]),
    [{active, false},
     {verify, 0},
     {mode,binary},
     {reuseaddr, true},

     {versions, ['dtlsv1.2', dtlsv1]},
     {cb_info, ssl_udp},
     {verify_client_hello, true},

     {ciphers,
      [


       {dh_anon,aes_256_gcm,null}]},

     %% {psk_identity, "HINT"},
     %% {user_lookup_fun, {fun user_lookup/3, <<16#11>>}},
     %% {ciphers,[{rsa_psk, aes_256_cbc, sha}]},
     %% {ciphers,[{srp_dss, aes_256_cbc, sha}]},
     %% {ciphers, [{srp_anon, aes_256_cbc, sha}]}
     %% {ciphers,[{ecdh_rsa,aes_256_gcm,null}]},
     %% {cacertfile, "/usr/src/erlang/otp/tls-gcm/release/tests/test_server/ct_run.test_server@ws006-lx.2013-03-04_19.56.33/tests.ssl_test.logs/run.2013-03-04_19.56.34/log_private/client/rsa_rsa_cacerts.pem"},
     %% {certfile, "/usr/src/erlang/otp/tls-gcm/release/tests/test_server/ct_run.test_server@ws006-lx.2013-03-04_19.56.33/tests.ssl_test.logs/run.2013-03-04_19.56.34/log_private/client/rsa_ec_cert.pem"},
     %% {keyfile, "/usr/src/erlang/otp/tls-gcm/release/tests/test_server/ct_run.test_server@ws006-lx.2013-03-04_19.56.33/tests.ssl_test.logs/run.2013-03-04_19.56.34/log_private/client/rsa_ec_key.pem"}].
     %% {cacertfile, "/usr/src/erlang/otp/tls-gcm/release/tests/test_server/ct_run.test_server@ws006-lx.2013-03-04_19.56.33/tests.ssl_test.logs/run.2013-03-04_19.56.34/log_private/server/dsa_cacerts.pem"},
     %% {certfile, "/usr/src/erlang/otp/tls-gcm/release/tests/test_server/ct_run.test_server@ws006-lx.2013-03-04_19.56.33/tests.ssl_test.logs/run.2013-03-04_19.56.34/log_private/server/dsa_cert.pem"},
     %% {keyfile, "/usr/src/erlang/otp/tls-gcm/release/tests/test_server/ct_run.test_server@ws006-lx.2013-03-04_19.56.33/tests.ssl_test.logs/run.2013-03-04_19.56.34/log_private/server/dsa_key.pem"}].

     {cacertfile, filename:join([Dir, Role, "cacerts.pem"])},
     {certfile, filename:join([Dir, Role, "cert.pem"])},
     {keyfile, filename:join([Dir, Role, "key.pem"])}
    ].

server_loop(ListenSocket) ->
    {ok, Socket} = ssl:transport_accept(ListenSocket),
    io:format("accepted connection from ~p\n", [ssl:peername(Socket)]),
    ssl:ssl_accept(Socket),
    spawn(fun() -> loop(Socket) end),
    server_loop(ListenSocket).

udp_server_loop(ListenSocket) ->
    {ok, Socket} = ssl:transport_accept(ListenSocket),
    ssl:ssl_accept(Socket),
    spawn(fun() -> loop(Socket) end),
    udp_server_loop(ListenSocket).

loop(Socket) ->
    io:format("waiting for packet~n"),
    renegotiate(Socket, "Data"),
    case ssl:recv(Socket, 0, 2000) of
        {ok, Data} ->
            io:format("received data: ~s~n", [binary_to_list(Data)]),
            Return = ssl:send(Socket, Data),
            io:format("sending ~p~n", [Return]),
	    io:format("Socket: ~p~n", [ssl:session_info(Socket)]),
            loop(Socket);
        {error, timeout} ->
           loop(Socket);
        Else ->
            io:format("crap ~p~n",[Else])
    end.


% hexstr2bin
hexstr2bin(S) ->
    list_to_binary(hexstr2list(S)).

hexstr2list([X,Y|T]) ->
    [mkint(X)*16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
    [].

mkint(C) when $0 =< C, C =< $9 ->
    C - $0;
mkint(C) when $A =< C, C =< $F ->
    C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
    C - $a + 10.
