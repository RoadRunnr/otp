%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2013-2014. All Rights Reserved.
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
-module(dtls_connection).

%% Internal application API

-behaviour(gen_fsm).

-include("dtls_connection.hrl").
-include("dtls_handshake.hrl").
-include("ssl_alert.hrl").
-include("dtls_record.hrl").
-include("ssl_cipher.hrl").
-include("ssl_api.hrl").
-include("ssl_internal.hrl").
-include("ssl_srp.hrl").
-include_lib("public_key/include/public_key.hrl"). 

%% Internal application API

%% Setup
-export([start_fsm/8]).

%% State transition handling	 
-export([next_record/1, next_state/4%, 
	 %%next_state_connection/2
	]).

%% Handshake handling
-export([%%renegotiate/1, 
	 send_handshake/2, send_change_cipher/2]).

%% Alert and close handling
-export([send_alert/2, handle_own_alert/4, %%handle_close_alert/3,
	 handle_normal_shutdown/3
	 %%handle_unexpected_message/3,
	 %%alert_user/5, alert_user/8
	]).

%% Data handling
-export([%%write_application_data/3, 
	 read_application_data/2,
%%	 passive_receive/2,  next_record_if_active/1
	 handle_packet/3
	]).


%% Called by tls_connection_sup
-export([start_link/7]). 

%% gen_fsm callbacks
-export([init/1, hello/2, certify/2, cipher/2,
	 abbreviated/2, connection/2, handle_event/3,
         handle_sync_event/4, handle_info/3, terminate/3, code_change/4]).

%%====================================================================
%% Internal application API
%%====================================================================	     
start_fsm(Role, Host, Port, Socket, {#ssl_options{erl_dist = false},_} = Opts,
	  User, {CbModule, _,_, _} = CbInfo, 
	  Timeout) -> 
    try 
	{ok, Pid} = dtls_connection_sup:start_child([Role, Host, Port, Socket, 
						     Opts, User, CbInfo]), 
	{ok, SslSocket} = ssl_connection:socket_control(?MODULE, Socket, Pid, CbModule),
	ok = ssl_connection:handshake(SslSocket, Timeout),
	{ok, SslSocket} 
    catch
	error:{badmatch, {error, _} = Error} ->
	    Error
    end;

start_fsm(Role, Host, Port, Socket, {#ssl_options{erl_dist = true},_} = Opts,
	  User, {CbModule, _,_, _} = CbInfo, 
	  Timeout) -> 
    try 
	{ok, Pid} = dtls_connection_sup:start_child_dist([Role, Host, Port, Socket, 
							  Opts, User, CbInfo]), 
	{ok, SslSocket} = ssl_connection:socket_control(?MODULE, Socket, Pid, CbModule),
	ok = ssl_connection:handshake(SslSocket, Timeout),
	{ok, SslSocket} 
    catch
	error:{badmatch, {error, _} = Error} ->
	    Error
    end.

send_handshake(Handshake, #state{negotiated_version = Version,
				 tls_handshake_history = Hist0,
				 connection_states = ConnectionStates0} = State0) ->
    {BinHandshake, ConnectionStates, Hist} =
	encode_handshake(Handshake, Version, ConnectionStates0, Hist0),
    send_flight(BinHandshake, State0#state{connection_states = ConnectionStates,
					   tls_handshake_history = Hist
					  }).

send_alert(Alert, #state{negotiated_version = Version,
			 socket = Socket,
			 transport_cb = Transport,
			 connection_states = ConnectionStates0} = State0) ->
    {BinMsg, ConnectionStates} =
	ssl_alert:encode(Alert, Version, ConnectionStates0),
    Transport:send(Socket, BinMsg),
    State0#state{connection_states = ConnectionStates}.

send_change_cipher(Msg, #state{connection_states = ConnectionStates0,
			       socket = Socket,
			       negotiated_version = Version,
			       transport_cb = Transport} = State0) ->
    {BinChangeCipher, ConnectionStates} =
	encode_change_cipher(Msg, Version, ConnectionStates0),
    Transport:send(Socket, BinChangeCipher),
    State0#state{connection_states = ConnectionStates}.

%%====================================================================
%% tls_connection_sup API
%%====================================================================

%%--------------------------------------------------------------------
-spec start_link(atom(), host(), inet:port_number(), port(), list(), pid(), tuple()) ->
    {ok, pid()} | ignore |  {error, reason()}.
%%
%% Description: Creates a gen_fsm process which calls Module:init/1 to
%% initialize. To ensure a synchronized start-up procedure, this function
%% does not return until Module:init/1 has returned.  
%%--------------------------------------------------------------------
start_link(Role, Host, Port, Socket, Options, User, CbInfo) ->
    {ok, proc_lib:spawn_link(?MODULE, init, [[Role, Host, Port, Socket, Options, User, CbInfo]])}.

init([Role, Host, Port, Socket, Options,  User, CbInfo]) ->
    process_flag(trap_exit, true),
    State = initial_state(Role, Host, Port, Socket, Options, User, CbInfo),
    gen_fsm:enter_loop(?MODULE, [], hello, State, get_timeout(State)).

%%--------------------------------------------------------------------
%% Description:There should be one instance of this function for each
%% possible state name. Whenever a gen_fsm receives an event sent
%% using gen_fsm:send_event/2, the instance of this function with the
%% same name as the current state name StateName is called to handle
%% the event. It is also called if a timeout occurs.
%%
hello(start, #state{host = Host, port = Port, role = client,
		    ssl_options = SslOpts,
		    session = #session{own_certificate = Cert} = Session0,
		    session_cache = Cache, session_cache_cb = CacheCb,
		    transport_cb = Transport, socket = Socket,
		    connection_states = ConnectionStates0,
		    renegotiation = {Renegotiation, _}} = State0) ->
    Hello = dtls_handshake:client_hello(Host, Port, ConnectionStates0, SslOpts,
					Cache, CacheCb, Renegotiation, Cert),
    
    Version = Hello#client_hello.client_version,
    Handshake0 = ssl_handshake:init_handshake_history(),
    {BinMsg, ConnectionStates, Handshake} =
        encode_handshake(Hello, Version, ConnectionStates0, Handshake0),
    Transport:send(Socket, BinMsg),
    State1 = State0#state{connection_states = ConnectionStates,
			  negotiated_version = Version, %% Requested version
			  session =
			      Session0#session{session_id = Hello#client_hello.session_id},
			  tls_handshake_history = Handshake},
    {Record, State} = next_record(State1),
    next_state(hello, hello, Record, State);

hello(Hello = #client_hello{client_version = ClientVersion,
			    extensions = #hello_extensions{hash_signs = HashSigns}},
      State = #state{connection_states = ConnectionStates0,
		     port = Port, session = #session{own_certificate = Cert} = Session0,
		     renegotiation = {Renegotiation, _},
		     session_cache = Cache,
		     session_cache_cb = CacheCb,
		     ssl_options = SslOpts}) ->
    case dtls_handshake:hello(Hello, SslOpts, {Port, Session0, Cache, CacheCb,
					      ConnectionStates0, Cert}, Renegotiation) of
        {Version, {Type, Session},
	 ConnectionStates,
	 #hello_extensions{ec_point_formats = EcPointFormats,
			   elliptic_curves = EllipticCurves} = ServerHelloExt} ->
            HashSign = ssl_handshake:select_hashsign(HashSigns, Cert, 
						     dtls_v1:corresponding_tls_version(Version)),
            ssl_connection:hello({common_client_hello, Type, ServerHelloExt, HashSign},
				 State#state{connection_states  = ConnectionStates,
					     negotiated_version = Version,
					     session = Session,
					     client_ecc = {EllipticCurves, EcPointFormats}}, ?MODULE);
        #alert{} = Alert ->
            handle_own_alert(Alert, ClientVersion, hello, State)
    end;
hello(Hello,
      #state{connection_states = ConnectionStates0,
	     negotiated_version = ReqVersion,
	     role = client,
	     renegotiation = {Renegotiation, _},
	     ssl_options = SslOptions} = State) ->
    case dtls_handshake:hello(Hello, SslOptions, ConnectionStates0, Renegotiation) of
	#alert{} = Alert ->
	    handle_own_alert(Alert, ReqVersion, hello, State);
	{Version, NewId, ConnectionStates, NextProtocol} ->
	    ssl_connection:handle_session(Hello, 
					  Version, NewId, ConnectionStates, NextProtocol, State)
    end;

hello(Msg, State) ->
    ssl_connection:hello(Msg, State, ?MODULE).

abbreviated(Msg, State) ->
    ssl_connection:abbreviated(Msg, State, ?MODULE).

certify(Msg, State) ->
    ssl_connection:certify(Msg, State, ?MODULE).

cipher(Msg, State) ->
     ssl_connection:cipher(Msg, State, ?MODULE).

connection(#hello_request{}, #state{host = Host, port = Port,
				    session = #session{own_certificate = Cert} = Session0,
				    session_cache = Cache, session_cache_cb = CacheCb,
				    ssl_options = SslOpts,
				    connection_states = ConnectionStates0,
				    renegotiation = {Renegotiation, _}} = State0) ->
    Hello = dtls_handshake:client_hello(Host, Port, ConnectionStates0, SslOpts,
					Cache, CacheCb, Renegotiation, Cert),
    %% TODO DTLS version State1 = send_handshake(Hello, State0),
    State1 = State0,
    {Record, State} =
	next_record(
	  State1#state{session = Session0#session{session_id
						  = Hello#client_hello.session_id}}),
    next_state(connection, hello, Record, State);

connection(#client_hello{} = Hello, #state{role = server, allow_renegotiate = true} = State) ->
    %% Mitigate Computational DoS attack
    %% http://www.educatedguesswork.org/2011/10/ssltls_and_computational_dos.html
    %% http://www.thc.org/thc-ssl-dos/ Rather than disabling client
    %% initiated renegotiation we will disallow many client initiated
    %% renegotiations immediately after each other.
    erlang:send_after(?WAIT_TO_ALLOW_RENEGOTIATION, self(), allow_renegotiate),
    hello(Hello, State#state{allow_renegotiate = false});

connection(#client_hello{}, #state{role = server, allow_renegotiate = false} = State0) ->
    Alert = ?ALERT_REC(?WARNING, ?NO_RENEGOTIATION),
    State = send_alert(Alert, State0),
    next_state_connection(connection, State);
  
connection(Msg, State) ->
     ssl_connection:connection(Msg, State, tls_connection).

%%--------------------------------------------------------------------
%% Description: Whenever a gen_fsm receives an event sent using
%% gen_fsm:send_all_state_event/2, this function is called to handle
%% the event. Not currently used!
%%--------------------------------------------------------------------
handle_event(_Event, StateName, State) ->
    {next_state, StateName, State, get_timeout(State)}.

%%--------------------------------------------------------------------
%% Description: Whenever a gen_fsm receives an event sent using
%% gen_fsm:sync_send_all_state_event/2,3, this function is called to handle
%% the event.
%%--------------------------------------------------------------------
handle_sync_event(Event, From, StateName, State) ->
    ssl_connection:handle_sync_event(Event, From, StateName, State).

%%--------------------------------------------------------------------
%% Description: This function is called by a gen_fsm when it receives any
%% other message than a synchronous or asynchronous event
%% (or a system message).
%%--------------------------------------------------------------------

%% raw data from socket, unpack records
handle_info({Protocol, _, Data}, StateName,
            #state{data_tag = Protocol} = State0) ->
    %% Simplify for now to avoid dialzer warnings before implementation is  compleate
    %% case next_tls_record(Data, State0) of
    %% 	{Record, State} ->
    %% 	    next_state(StateName, StateName, Record, State);
    %% 	#alert{} = Alert ->
    %% 	    handle_normal_shutdown(Alert, StateName, State0), 
    %% 	    {stop, {shutdown, own_alert}, State0}
    %% end;
    {Record, State} = next_tls_record(Data, State0), 
    next_state(StateName, StateName, Record, State);

handle_info({CloseTag, Socket}, StateName,
            #state{socket = Socket, close_tag = CloseTag,
		   negotiated_version = _Version} = State) ->
    handle_normal_shutdown(?ALERT_REC(?FATAL, ?CLOSE_NOTIFY), StateName, State),
    {stop, {shutdown, transport_closed}, State};

handle_info(Msg, StateName, State) ->
    ssl_connection:handle_info(Msg, StateName, State).

%%--------------------------------------------------------------------
%% Description:This function is called by a gen_fsm when it is about
%% to terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_fsm terminates with
%% Reason. The return value is ignored.
%%--------------------------------------------------------------------
terminate(Reason, StateName, State) ->
    ssl_connection:terminate(Reason, StateName, State).

%%--------------------------------------------------------------------
%% code_change(OldVsn, StateName, State, Extra) -> {ok, StateName, NewState}
%% Description: Convert process state when code is changed
%%--------------------------------------------------------------------
code_change(_OldVsn, StateName, State, _Extra) ->
    {ok, StateName, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
encode_handshake(Handshake, Version, ConnectionStates0, Hist0) ->
    Seq = sequence(ConnectionStates0),
    {EncHandshake, FragmentedHandshake} = dtls_handshake:encode_handshake(Handshake, Version,
								      Seq, 1400),
    Hist = ssl_handshake:update_handshake_history(Hist0, EncHandshake),
    {Encoded, ConnectionStates} =
        dtls_record:encode_handshake(FragmentedHandshake, 
				     Version, ConnectionStates0),
    {Encoded, ConnectionStates, Hist}.

next_record(#state{%%flight = #flight{state = finished}, 
		   protocol_buffers =
		       #protocol_buffers{dtls_packets = [], dtls_cipher_texts = [CT | Rest]}
		   = Buffers,
		   connection_states = ConnStates0} = State) ->
    case dtls_record:decode_cipher_text(CT, ConnStates0) of
	{Plain, ConnStates} ->		      
	    {Plain, State#state{protocol_buffers =
				    Buffers#protocol_buffers{dtls_cipher_texts = Rest},
				connection_states = ConnStates}};
	#alert{} = Alert ->
	    {Alert, State}
    end;
next_record(#state{socket = Socket,
		   transport_cb = Transport} = State) -> %% when FlightState =/= finished
    ssl_socket:setopts(Transport, Socket, [{active,once}]),
    {no_record, State};


next_record(State) ->
    {no_record, State}.

next_state(Current,_, #alert{} = Alert, #state{negotiated_version = Version} = State) ->
    handle_own_alert(Alert, Version, Current, State);

next_state(_,Next, no_record, State) ->
    {next_state, Next, State, get_timeout(State)};

%% next_state(_,Next, #ssl_tls{type = ?ALERT, fragment = EncAlerts}, State) ->
%%     Alerts = decode_alerts(EncAlerts),
%%     handle_alerts(Alerts,  {next_state, Next, State, get_timeout(State)});

next_state(Current, Next, #ssl_tls{type = ?HANDSHAKE, fragment = Data},
	   State0 = #state{protocol_buffers =
			       #protocol_buffers{dtls_handshake_buffer = Buf0} = Buffers,
			   negotiated_version = Version}) ->
    Handle = 
   	fun({#hello_request{} = Packet, _}, {next_state, connection = SName, State}) ->
   		%% This message should not be included in handshake
   		%% message hashes. Starts new handshake (renegotiation)
		Hs0 = ssl_handshake:init_handshake_history(),
		?MODULE:SName(Packet, State#state{tls_handshake_history=Hs0,
   						  renegotiation = {true, peer}});
   	   ({#hello_request{} = Packet, _}, {next_state, SName, State}) ->
   		%% This message should not be included in handshake
   		%% message hashes. Already in negotiation so it will be ignored!
   		?MODULE:SName(Packet, State);
	   ({#client_hello{} = Packet, Raw}, {next_state, connection = SName, State}) ->
		Version = Packet#client_hello.client_version,
		Hs0 = ssl_handshake:init_handshake_history(),
		Hs1 = ssl_handshake:update_handshake_history(Hs0, Raw),
		?MODULE:SName(Packet, State#state{tls_handshake_history=Hs1,
   						  renegotiation = {true, peer}});
	   ({Packet, Raw}, {next_state, SName, State = #state{tls_handshake_history=Hs0}}) ->
		Hs1 = ssl_handshake:update_handshake_history(Hs0, Raw),
		?MODULE:SName(Packet, State#state{tls_handshake_history=Hs1});
   	   (_, StopState) -> StopState
   	end,
    try
	{Packets, Buf} = tls_handshake:get_tls_handshake(Version,Data,Buf0),
	State = State0#state{protocol_buffers =
				 Buffers#protocol_buffers{dtls_packets = Packets,
							  dtls_handshake_buffer = Buf}},
	handle_dtls_handshake(Handle, Next, State)
    catch throw:#alert{} = Alert ->
	    handle_own_alert(Alert, Version, Current, State0)
    end;

next_state(_, StateName, #ssl_tls{type = ?APPLICATION_DATA, fragment = Data}, State0) ->
    %% Simplify for now to avoid dialzer warnings before implementation is  compleate
    %% case read_application_data(Data, State0) of
    %% 	Stop = {stop,_,_} ->
    %% 	    Stop;
    %% 	{Record, State} ->
    %% 	    next_state(StateName, StateName, Record, State)
    %% end;
    {Record, State} = read_application_data(Data, State0),
    next_state(StateName, StateName, Record, State);
	
next_state(Current, Next, #ssl_tls{type = ?CHANGE_CIPHER_SPEC, fragment = <<1>>} = 
 	   _ChangeCipher, 
 	   #state{connection_states = ConnectionStates0} = State0) ->
    ConnectionStates1 =
	ssl_record:activate_pending_connection_state(ConnectionStates0, read),
    {Record, State} = next_record(State0#state{connection_states = ConnectionStates1}),
    next_state(Current, Next, Record, State);
next_state(Current, Next, #ssl_tls{type = _Unknown}, State0) ->
    %% Ignore unknown type 
    {Record, State} = next_record(State0),
    next_state(Current, Next, Record, State).

handle_dtls_handshake(Handle, StateName,
		     #state{protocol_buffers =
				#protocol_buffers{dtls_packets = [Packet]} = Buffers} = State) ->
    FsmReturn = {next_state, StateName, State#state{protocol_buffers =
							Buffers#protocol_buffers{dtls_packets = []}}},
    Handle(Packet, FsmReturn);

handle_dtls_handshake(Handle, StateName,
		     #state{protocol_buffers =
				#protocol_buffers{dtls_packets = [Packet | Packets]} = Buffers} =
			 State0) ->
    FsmReturn = {next_state, StateName, State0#state{protocol_buffers =
							 Buffers#protocol_buffers{dtls_packets =
										      Packets}}},
    case Handle(Packet, FsmReturn) of
	{next_state, NextStateName, State, _Timeout} ->
	    handle_dtls_handshake(Handle, NextStateName, State);
	{stop, _,_} = Stop ->
	    Stop
    end.


send_flight(Fragments, #state{transport_cb = Transport, socket = Socket,
			      protocol_buffers = _PBuffers} = State) ->
    Transport:send(Socket, Fragments),
    %% Start retransmission
    %% State#state{protocol_buffers = 
    %% 		    (PBuffers#protocol_buffers){ #flight{state = waiting}}}}.
    State.

handle_own_alert(_,_,_, State) -> %% Place holder
    {stop, {shutdown, own_alert}, State}.

handle_normal_shutdown(_, _, _State) -> %% Place holder
    ok.

encode_change_cipher(#change_cipher_spec{}, Version, ConnectionStates) -> 
    dtls_record:encode_change_cipher_spec(Version, ConnectionStates).

initial_state(Role, Host, Port, Socket, {SSLOptions, SocketOptions, Tracker}, User,
	      {CbModule, DataTag, CloseTag, ErrorTag}) ->
    ConnectionStates = ssl_record:init_connection_states(Role),
    
    SessionCacheCb = case application:get_env(ssl, session_cb) of
			 {ok, Cb} when is_atom(Cb) ->
			    Cb;
			 _  ->
			     ssl_session_cache
		     end,
    
    Monitor = erlang:monitor(process, User),

    #state{socket_options = SocketOptions,
	   ssl_options = SSLOptions,
	   session = #session{is_resumable = new},
	   transport_cb = CbModule,
	   data_tag = DataTag,
	   close_tag = CloseTag,
	   error_tag = ErrorTag,
	   role = Role,
	   host = Host,
	   port = Port,
	   socket = Socket,
	   connection_states = ConnectionStates,
	   protocol_buffers = #protocol_buffers{},
	   user_application = {Monitor, User},
	   user_data_buffer = <<>>,
	   session_cache_cb = SessionCacheCb,
	   renegotiation = {false, first},
	   start_or_recv_from = undefined,
	   send_queue = queue:new(),
	   protocol_cb = ?MODULE,
	   tracker = Tracker
	  }.
read_application_data(_,State) ->
    {#ssl_tls{fragment = <<"place holder">>}, State}.
	
next_tls_record(_, State) ->
    {#ssl_tls{fragment = <<"place holder">>}, State}.

get_timeout(_) -> %% Place holder
    infinity.

next_state_connection(_, State) -> %% Place holder
    {next_state, connection, State, get_timeout(State)}.

sequence(_) -> 
    %%TODO real imp
    1.

handle_packet(Address, Port, Packet) ->
    try dtls_record:get_dtls_records(Packet, <<>>) of
	%% expect client hello
	{[#ssl_tls{type = ?HANDSHAKE, version = {254, _}} = Record], <<>>} ->
	    handle_dtls_client_hello(Address, Port, Record);
	Other ->
	    {error, not_dtls}
    catch
	Class:Error ->
	    {error, not_dtls}
    end.

handle_dtls_client_hello(Address, Port,
			 #ssl_tls{epoch = Epoch, sequence_number = Seq,
				  version = Version} = Record) ->
    {[{Hello, _}], _} =
	dtls_handshake:get_dtls_handshake(Record,
					 dtls_handshake:dtls_handshake_new_flight(undefined)),
    #client_hello{client_version = {Major, Minor},
		  random = Random,
		  session_id = SessionId,
		  cipher_suites = CipherSuites,
		  compression_methods = CompressionMethods} = Hello,
    CookieData = [address_to_bin(Address, Port),
		  <<?BYTE(Major), ?BYTE(Minor)>>,
		  Random, SessionId, CipherSuites, CompressionMethods],
    Cookie = crypto:hmac(sha, <<"secret">>, CookieData),

    case Hello of
	#client_hello{cookie = Cookie} ->
	    io:format("DTLS: Accept~n"),
	    accept;

	_ ->
	    %% generate HelloVerifyRequest
	    {RequestFragment, _} = dtls_handshake:encode_handshake(
				     dtls_handshake:hello_verify_request(Cookie),
				     Version, 0, 1400),
	    HelloVerifyRequest =
		dtls_record:encode_plain_text(?HANDSHAKE, Version, Epoch, Seq, RequestFragment),
	    {reply, HelloVerifyRequest}
    end.

address_to_bin({A,B,C,D}, Port) ->
    <<0:80,16#ffff:16,A,B,C,D,Port:16>>;
address_to_bin({A,B,C,D,E,F,G,H}, Port) ->
    <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16,Port:16>>.
