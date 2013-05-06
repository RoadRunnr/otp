%%
%% %CopyrightBegin%
%% 
%% Copyright Ericsson AB 2003-2009. All Rights Reserved.
%% 
%% The contents of this file are subject to the Erlang Public License,
%% Version 1.1, (the "License"); you may not use this file except in
%% compliance with the License. You should have received a copy of the
%% Erlang Public License along with this software. If not, it can be
%% retrieved online at http://www.erlang.org/.
%% 
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and limitations
%% under the License.
%% 
%% %CopyrightEnd%
%%

%%% Purpose: Example of SSL client.

-module(dtls_anon_client).

-export([connect/1]).

psk_verify(Username, UserState) ->
    io:format("Server Hint: ~p~n", [Username]),
    {ok, UserState}.

connect(Port) ->
    application:start(crypto),
    application:start(public_key),
    application:start(ssl),

    %% Opts = [{ciphers,[{dhe_dss,aes_256_cbc,sha256}]},
    Opts = [
	    {ssl_imp,new},
	    {active, false},
	    {verify, 0},

	    {versions, ['dtlsv1.2', dtlsv1]},
	    {cb_info, ssl_udp},
	    %% {ciphers,[{rsa, aes_256_cbc, sha}]}

	    {ciphers,
	     [{dh_anon,rc4_128,md5},
	      {dh_anon,des_cbc,sha},
	      {dh_anon,'3des_ede_cbc',sha},
	      {dh_anon,aes_128_cbc,sha},
	      {dh_anon,aes_256_cbc,sha},
	      {ecdh_anon,rc4_128,sha},
	      {ecdh_anon,'3des_ede_cbc',sha},
	      {ecdh_anon,aes_128_cbc,sha},
	      {ecdh_anon,aes_256_cbc,sha},
	      {dh_anon,aes_128_gcm,null},
	      {dh_anon,aes_256_gcm,null}]}

	    %% {srp_identity, {"Test-User", "secret"}},
	    %% {ciphers, [{srp_anon, aes_256_cbc, sha}]},
	    %% {psk_identity, "Client_identity"},
	    %% {psk_lookup_fun, {fun psk_verify/2, <<16#11>>}},
	    %% {versions, [tlsv1]},
	    %% {ciphers,[{rsa_psk, aes_256_cbc, sha}]},
	    %% {reuseaddr,true}
	   ],

    %%{ok, Host} = inet:gethostname(),
    Host = {127,0,0,1},
    {ok, CSock} = ssl:connect(Host, Port, Opts),
    io:fwrite("Connect: connected.~n"),
    {ok, Data} = ssl:recv(CSock, 0),
    io:fwrite("Connect: got data: ~p~n", [Data]),
    io:fwrite("Connect: closing and terminating.~n"),
    ssl:close(CSock).
