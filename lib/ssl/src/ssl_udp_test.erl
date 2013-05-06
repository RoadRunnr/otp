%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 1999-2013. All Rights Reserved.
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

%%

%%% Purpose : UDP API Wrapper

-module(ssl_udp_test).

-behavior(gen_server).

-export([connect/3, connect/4, accept/2, listen/2, close/1, controlling_process/2]).
-export([send/2, handle_ssl_info/2]).
-export([getopts/2, setopts/2, port/1, peername/1, sockname/1]).
-export([connection_type/1, callback_info/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(PROTOCOL, ?MODULE).

%% -export([send/2,
%% 	 recv/2, recv/3, controlling_process/2, close/1, shutdown/2]).

connect(Address, Port, Options, _Timeout) ->
    connect(Address, Port, Options).

connect(Address, Port, Opts0) ->
    Options = lists:filter(fun({packet, _}) -> false;
			      ({packet_size, _}) -> false;
			      (_) -> true end, Opts0),
    case gen_udp:open(0, Options) of
	{ok, Socket} ->
	    case gen_udp:connect(Socket, Address, Port) of
		ok ->
		    {ok, Socket};
		Error = {error, _Reason} ->
		    Error
	    end;
	Error = {error, _Reason} ->
	    Error
    end.

accept(ListenSocket, Timeout) ->
    call(ListenSocket, accept, Timeout, infinity).

listen(Port, Options) ->
%%    gen_server:start_link(?MODULE, [Port, Options], [{debug, [trace]}]).
    gen_server:start_link(?MODULE, [Port, Options], []).

controlling_process(Socket, Pid) when is_port(Socket) ->
    gen_udp:controlling_process(Socket, Pid);
controlling_process(Socket, Pid) ->
    call(Socket, controlling_process, Pid).

close(Socket) when is_port(Socket) ->
    gen_udp:close(Socket);
close(Socket) ->
    call(Socket, close, undefined).

send(Socket, Data) when is_port(Socket) ->
    gen_udp:send(Socket, Data);
send(Socket, Data) ->
    call(Socket, send, Data).

%% map UDP port info's to three-tupple format
handle_ssl_info(Socket, {udp, Socket, _Address, _Port, Packet}) ->
    {next, {?PROTOCOL, Socket, Packet}};
handle_ssl_info(_, Info) ->
    Info.

getopts(Socket, Options) when is_port(Socket) ->
    inet:getopts(Socket, Options);
getopts(Socket, Options) ->
    call(Socket, getopts, Options).

setopts(Socket, Options) when is_port(Socket) ->
    inet:setopts(Socket, Options);
setopts(Socket, Options) ->
    call(Socket, setopts, Options).

peername(Socket) when is_port(Socket) ->
    inet:peername(Socket);
peername(Socket) ->
    call(Socket, peername, undefined).

sockname(Socket) when is_port(Socket) ->
    inet:sockname(Socket);
sockname(Socket) ->
    call(Socket, sockname, undefined).

port(Socket) when is_port(Socket) ->
    inet:port(Socket);
port(Socket) ->
    call(Socket, port, undefined).

connection_type(_Socket) ->
    datagram.

callback_info() ->
    {?MODULE, ?PROTOCOL, udp_closed, udp_error}.

%%----------------------------------
%% Port Logic
%%----------------------------------

call(Socket, Request, Args) ->
    call(Socket, Request, Args, 5000).

call(Socket, Request, Args, Timeout) when is_pid(Socket) ->
    gen_server:call(Socket, {Request, undefined, Args}, Timeout);
call({Socket, SslSocket}, Request, Args, Timeout) when is_pid(Socket) ->
    gen_server:call(Socket, {Request, SslSocket, Args}, Timeout).

ssl_socket(SslSocketId) ->
    {self(), SslSocketId}.

-record(state, {socket, ip_conns, ssl_conns, accepting, msg_seq}).
-record(ssl_socket, {id, owner, mode, queue, msg_seq, msg_q}).

init([Port, Options]) ->
    MsgSeq = application:get_env(ssl, dtls_msg_seq, []),
    Opts = lists:keystore(active, 1, Options, {active, true}),
    case gen_udp:open(Port, Opts) of
	{ok, Socket} ->
	    {ok, #state{socket = Socket,
			ip_conns = gb_trees:empty(),
			ssl_conns = gb_trees:empty(),
			msg_seq = MsgSeq}};
	Error ->
	    Error
    end.

terminate(_Reason, _State) ->
    ok.

handle_call({accept, _, Timeout}, From, State = #state{accepting = undefined}) ->
    {noreply, State#state{accepting = From}, Timeout};
handle_call({accept, _, _Timeout}, _From, State) ->
    {reply, {error, already_listening}, State};

handle_call({close, SslSocketId, _}, _From,
	    State = #state{ip_conns = IpConns0, ssl_conns = SslConns0}) ->
    case gb_trees:lookup(SslSocketId, SslConns0) of
	none ->
	    {reply, {error, enotconnected}, State};
	{value, IpKey} ->
	    IpConns = gb_trees:delete_any(IpKey, IpConns0),
	    SslConns = gb_trees:delete_any(SslSocketId, SslConns0),
	    {reply, ok, State#state{ip_conns = IpConns, ssl_conns = SslConns}}
    end;

handle_call({getopts, undefined, Options}, _From, State = #state{socket = Socket}) ->
    Reply = inet:getopts(Socket, Options),
    {reply, Reply, State};
handle_call({setopts, undefined, Options}, _From, State = #state{socket = Socket}) ->
    Opts = lists:keystore(active, 1, Options, {active, true}),
    Reply = inet:setopts(Socket, Opts),
    {reply, Reply, State};

handle_call({send, SslSocketId, Packet}, _From, State = #state{socket = Socket, ssl_conns = SslConns}) ->
    case gb_trees:lookup(SslSocketId, SslConns) of
	none ->
	    {reply, {error, enotconnected}, State};
	{value, {Address, Port}} ->
	    Reply = send(Socket, Address, Port, Packet),
	    io:format("ssl_udp:send -> ~p~n", [Reply]),
	    {reply, Reply, State}
    end;

handle_call({setopts, SslSocketId, Options}, _From,
	    State = #state{ip_conns = IpConns0, ssl_conns = SslConns}) ->
    case proplists:get_value(active, Options) of
	Active when Active /= false ->
	    case gb_trees:lookup(SslSocketId, SslConns) of
		none ->
		    {reply, {error, enotconnected}, State};
		{value, IpKey} ->
		    SslSocket = gb_trees:get(IpKey, IpConns0),
		    #ssl_socket{owner = Owner, queue = Queue} = SslSocket,
		    [recv_packet(Owner, ssl_socket(SslSocketId), Packet) || Packet <- queue:to_list(Queue)],
		    IpConns1  = gb_trees:update(IpKey, SslSocket#ssl_socket{mode = active, queue = queue:new()}, IpConns0),
		    {reply, ok, State#state{ip_conns = IpConns1}}
	    end;
	_ ->
	    {reply, ok, State}
    end;

handle_call({peername, SslSocket, _}, _From, State = #state{ssl_conns = SslConns0}) ->
    case gb_trees:lookup(SslSocket, SslConns0) of
	none ->
	    {reply, {error, enotconnected}, State};
	{value, IpKey} ->
	    {reply, {ok, IpKey}, State}
    end;

handle_call({sockname, _, _}, _From, State = #state{socket = Socket}) ->
    Reply = inet:sockname(Socket),
    {reply, Reply, State};

handle_call({port, _, _}, _From, State = #state{socket = Socket}) ->
    Reply = inet:port(Socket),
    {reply, Reply, State};

handle_call({controlling_process, SslSocketId, Pid}, _From,
	    State = #state{ip_conns = IpConns0, ssl_conns = SslConns0}) ->
    case gb_trees:lookup(SslSocketId, SslConns0) of
	none ->
	    {reply, {error, enotconnected}, State};
	{value, IpKey} ->
	    SslSocket = gb_trees:get(IpKey, IpConns0),
	    IpConns1  = gb_trees:update(IpKey, SslSocket#ssl_socket{owner = Pid}, IpConns0),
	    {reply, ok, State#state{ip_conns = IpConns1}}
    end;

handle_call(Request, _From, State) ->
    io:format("unexpected requests ~p~n", [Request]),
    {reply, ok, State}.


%handle_call(Request, From, State = #state{socket = Socket, connections = Cons}) ->
handle_cast(Request, State) ->
    io:format("unexpected requests ~p~n", [Request]),
    {noreply, State}.

handle_info(timeout, State = #state{accepting = Accepting})
	    when Accepting /= undefined ->
    gen_server:reply(Accepting, {error, timeout}),
    {noreply, State#state{accepting = undefined}};

handle_info({udp, Socket, IP, InPortNo, Packet},
	    State0 = #state{socket = Socket, ip_conns = IpConns}) ->
    IpKey = {IP, InPortNo},
    State1 = case gb_trees:lookup(IpKey, IpConns) of
		 none ->
		     handle_accept(IpKey, Packet, State0);
		 {value, SslSocket} ->
		     handle_packet(IpKey, SslSocket, Packet, State0)
	    end,
    inet:setopts(Socket, [{active, once}]),
    {noreply, State1};

handle_info(Info, State) ->
    io:format("unexpected info:~n~p~n~p~n", [Info, State]),
    {noreply, State}.

handle_packet(IpKey, Socket0, Packet,
	      State = #state{ip_conns = IpConns0}) ->
    Socket1 = recv(Socket0, Packet),
    Socket2 = deliver_packet(Socket1),
    IpConns1 = gb_trees:update(IpKey, Socket2, IpConns0),
    State#state{ip_conns = IpConns1}.

deliver_packet(Socket = #ssl_socket{mode = passive}) ->
    Socket;
deliver_packet(Socket = #ssl_socket{id = SslSocketId,
				    owner = Owner,
				    mode = _Mode,
				    queue = Queue}) ->
    case queue:out(Queue) of
	{empty, _} ->
	    Socket;
	{{value, Packet}, Queue1} ->
	    recv_packet(Owner, ssl_socket(SslSocketId), Packet),
	    Socket#ssl_socket{queue = Queue1}
    end.

recv_packet(Owner, SslSocket, Packet) ->
    io:format("recv_packet: dequeueing packet~n~s~n", [ssl_handshake:hexdump(Packet)]),
    Owner ! {?PROTOCOL, SslSocket, Packet}.

handle_accept(_IpKey, _Packet, State = #state{accepting = undefined}) ->
    State;
handle_accept(IpKey = {Address, Port}, Packet,
	      State = #state{socket = Socket,
			     ip_conns = IpConns0, ssl_conns = SslConns0,
			     accepting = Accepting,
			     msg_seq = MsgSeq}) ->
    case ssl_datagram:handle_packet(Address, Port, Packet) of
	{reply, Data} ->
	    io:format("Reply: ~p~n", [Data]),
	    gen_udp:send(Socket, Address, Port, Data),
	    State;

	accept ->
	    %% NOTE: ClientHello's are decode twice, should this be changed?
	    {Owner, _} = Accepting,
	    SslSocketId = make_ref(),
	    SslSocket = #ssl_socket{id = SslSocketId,
				    owner = Owner,
				    mode = passive,
				    queue = queue:new(),
				    msg_seq = MsgSeq,
				    msg_q = gb_trees:empty()},
	    SslSocket1 = recv(SslSocket, Packet),
	    SslConns1 = gb_trees:insert(SslSocketId, IpKey, SslConns0),
	    IpConns1  = gb_trees:insert(IpKey, SslSocket1, IpConns0),
	    gen_server:reply(Accepting, {ok, ssl_socket(SslSocketId)}),
	    State#state{ip_conns = IpConns1, ssl_conns = SslConns1,
			accepting = undefined};

	_ ->
	    %% silently ignore
	    State
    end.


send(_Socket, _Address, _Port, []) ->
    ok;
send(Socket, Address, Port, [H|T]) ->
    case gen_udp:send(Socket, Address, Port, H) of
	ok ->
	    send(Socket, Address, Port, T);
	Other ->
	    Other
    end.

recv(SslSocket = #ssl_socket{queue = Queue, msg_seq = []},
     Packet) ->
    io:format("recv: queueing packet~n~s~n", [ssl_handshake:hexdump(Packet)]),
    SslSocket#ssl_socket{queue = queue:in(Packet, Queue)};
recv(SslSocket = #ssl_socket{msg_seq = [[Key|Rest]|T],
			     msg_q = MsgQ0},
     Packet) ->
    io:format("recv: queueing packet as ~w~n~s~n", [Key, ssl_handshake:hexdump(Packet)]),
    MsgQ = case Key of
	       drop -> MsgQ0;
	       _    -> gb_trees:insert(Key, Packet, MsgQ0)
	   end,
    case Rest of
	[] ->
	    Queue = queue:from_list(gb_trees:values(MsgQ)),
	    SslSocket#ssl_socket{queue = Queue,
				 msg_seq = T,
				 msg_q = gb_trees:empty()};
	_ ->
	    SslSocket#ssl_socket{msg_seq = [Rest|T],
				 msg_q = MsgQ}
    end.

