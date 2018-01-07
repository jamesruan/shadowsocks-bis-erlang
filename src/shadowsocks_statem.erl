%%%-------------------------------------------------------------------
%%% @author James Ruan <ruanbeihong@gmail.com>
%%% @copyright (C) 2017, James Raun
%%% @doc
%%% Proxying process, can be running as LOCAL instance or REMOTE instance
%%% - LOCAL instance provide an socks5 server to CLIENT and comunication
%%%   with REMOTE instance;
%%% - REMOTE instance relay requests from LOCAL instance to TARGET
%%%   server which CLIENT want to visit
%%% @end
%%%-------------------------------------------------------------------
-module(shadowsocks_statem).

-behaviour(gen_statem).

%% gen_statem callbacks
-export([callback_mode/0, init/1]).

%% API
-export([start_link/1, set_socket/2]).

%% state functions
-export(['L_SOCKET'/3
        ,'L_SOCKS5_AUTH'/3
        ,'L_SOCKS5_REQUEST'/3
        ,'L_IVEC'/3
        ,'L_DATA'/3
        ,'R_SOCKET'/3
        ,'R_IVEC'/3
        ,'R_TARGET_INFO'/3
        ,'R_DATA'/3
        ]).

-include("shadowsocks.hrl").

-record(state, {
          socket_client,
          socket_remote,
          client_addr,   %{host, port}
          remote_addr,   %{host, port}
          cipher_info,   %#cipher_info{}
          buf = <<>>
         }).

-define(TIMEOUT, 120000).

%%%===================================================================
%%% API
%%%===================================================================
start_link(Args) ->
    gen_statem:start_link(?MODULE, Args, []).

set_socket(Pid, Socket) when is_pid(Pid), is_port(Socket) ->
    gen_statem:cast(Pid, {socket_ready, Socket}).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================
callback_mode() ->
    state_functions.

init([local, _, ServerAddr, ServerPort, #cipher_info{}=CipherInfo]) ->
    process_flag(trap_exit, true),
    {ok, 'L_SOCKET', #state{remote_addr = {ServerAddr, ServerPort},
                                    cipher_info = CipherInfo}};
init([remote, _, #cipher_info{}=CipherInfo]) ->
    process_flag(trap_exit, true),
    {ok, 'R_SOCKET', #state{cipher_info = CipherInfo}}.

%%%===================================================================
%%% state functions
%%%===================================================================
%% LOCAL:
%%  L_SOCKET -> L_SOCKS5_AUTH -> L_SOCKS5_REQUEST ->
%%  L_IVEC -> L_DATA <-> L_DATA
%% REMOTE:
%%  R_SOCKET -> R_IVEC -> R_TARGET_INFO ->
%%  R_DATA <-> R_DATA


'L_SOCKET'(cast, {socket_ready, Socket}, State) ->
    inet:setopts(Socket, [{active, once}, {packet, raw}, binary]),
    {ok, Addr} = inet:peername(Socket),
    {next_state, 'L_SOCKS5_AUTH',
     State#state{socket_client=Socket, client_addr=Addr}, ?TIMEOUT};
'L_SOCKET'(cast, Other, State) ->
    ?ERROR("Unexpected message: ~p\n", [Other]),
    %% Allow to receive async messages
    {next_state, 'L_SOCKET', State};
'L_SOCKET'(info, Msg, StateData) ->
    handle_info(Msg, 'L_SOCKET', StateData).

'R_SOCKET'(cast, {socket_ready, Socket}, State)
  when is_port(Socket) ->
    inet:setopts(Socket, [{active, once}, {packet, raw}, binary]),
    {ok, {IP, _Port}} = inet:peername(Socket),
    {next_state, 'R_IVEC',
     State#state{socket_client=Socket, client_addr=IP}, ?TIMEOUT};
'R_SOCKET'(info, Msg, StateData) ->
    handle_info(Msg, 'R_SOCKET', StateData).

'L_SOCKS5_AUTH'(cast, {client, Data}, #state{socket_client=S} = State) ->
    Buffer = <<(State#state.buf)/binary, Data/binary>>,
    case decode_socks5_auth(Buffer) of
        incomplete ->
            {next_state, 'L_SOCKS5_AUTH',
             State#state{buf=Buffer}, ?TIMEOUT};
        {?SOCKS5_VER, _, _, Rest}->
            gen_tcp:send(S, <<?SOCKS5_VER, ?SOCKS5_AUTH_NONE>>),
            {next_state, 'L_SOCKS5_REQUEST',
             State#state{buf=Rest}, ?TIMEOUT};
        Error ->
            ?ERROR("'L_SOCKS5_AUTH' with error: ~p\n", [Error]),
            {stop, Error, State}
    end;
'L_SOCKS5_AUTH'(timeout, _, #state{client_addr=Addr}=State) ->
    ?ERROR("Client connection timeout: 'L_SOCKS5_AUTH', ~p\n",
           [Addr]),
    {stop, normal, State};
'L_SOCKS5_AUTH'(info, Msg, StateData) ->
    handle_info(Msg, 'L_SOCKS5_AUTH', StateData).

'L_SOCKS5_REQUEST'(cast, {client, Data}, #state{
                            socket_client=S, remote_addr={RemoteHost, RemotePort},
                            cipher_info=CipherInfo } = State) ->
    Buffer = <<(State#state.buf)/binary, Data/binary>>,
    case decode_socks5_req(Buffer) of
        incomplete ->
            {next_state, 'L_SOCKS5_REQUEST',
             State#state{buf=Buffer}, ?TIMEOUT};
        {?SOCKS5_VER, AddrType, Addr, Port, Rest}->
            Socks5Rsp = <<?SOCKS5_VER:8, ?SOCKS5_REP_OK:8,
                          ?SOCKS5_RESERVED_FIELD:8>>,
            Target = case AddrType of
                         ?SOCKS5_ATYP_V4 ->
                             BinAddr = list_to_binary(tuple_to_list(Addr)),
                             <<?SOCKS5_ATYP_V4:8, BinAddr/binary, Port:16>>;
                         ?SOCKS5_ATYP_DOM ->
                             BinAddr = list_to_binary(Addr),
                             AddrSize = size(BinAddr),
                             <<?SOCKS5_ATYP_DOM:8, AddrSize:8, BinAddr/binary, Port:16>>;
                         ?SOCKS5_ATYP_V6 ->
                             L = tuple_to_list(Addr),
                             BinAddr = list_to_binary([<<U:1/big-unit:16>> || U <- L]),
                             <<?SOCKS5_ATYP_V6:8, BinAddr/binary, Port:16>>
                     end,
            %% TODO: Rep after connect remote.
            gen_tcp:send(S, [Socks5Rsp, Target]),
            %% connect to remote server & send first message (IV included)
            {NewCipherInfo, EncodedTargert} =
                shadowsocks_crypt:encode(CipherInfo, Target),
            case gen_tcp:connect(RemoteHost, RemotePort, [{active, once},
                                                          {packet, raw}, binary]) of
                {ok, SocketRemote} ->
                    ?INFO("Connected to remote ~p:~p for proxying ~p:~p\n",
                          [RemoteHost, RemotePort, Addr, Port]),
                    gen_tcp:send(SocketRemote, EncodedTargert),
                    gen_tcp:send(SocketRemote, Rest),
                    {next_state, 'L_IVEC',
                     State#state{buf= <<>>, socket_remote=SocketRemote,
                                 cipher_info = NewCipherInfo}, ?TIMEOUT};
                {error, Reason} ->
                    ?ERROR("'L_SOCKS5_REQUEST' with error: ~p\n", [Reason]),
                    {stop, Reason, State}
            end;
        Error ->
            ?ERROR("'L_SOCKS5_REQUEST' with error: ~p\n", [Error]),
            {stop, Error, State}
    end;
'L_SOCKS5_REQUEST'(timeout, _, #state{client_addr=Addr}=State) ->
    ?ERROR("Client connection timeout: 'L_SOCKS5_REQUEST', ~p\n",
           [Addr]),
    {stop, normal, State};
'L_SOCKS5_REQUEST'(info, Msg, StateData) ->
    handle_info(Msg, 'L_SOCKS5_REQUEST', StateData).

'R_IVEC'(cast, {client, Data}, #state{
                  cipher_info=#cipher_info{
                    method=Method, key=Key, decode_iv=undefined}=CipherInfo}
                = State) ->
    Buffer = <<(State#state.buf)/binary, Data/binary>>,
    {_, IvLen} = shadowsocks_crypt:key_iv_len(Method),
    case decode_ivec(Buffer, IvLen) of
        incomplete ->
            {next_state, 'R_IVEC',
             State#state{buf=Buffer}, ?TIMEOUT};
        {Iv, Rest} ->
            StreamState = shadowsocks_crypt:stream_init(Method,Key,Iv),
            State1 = State#state{
                       buf = <<>>,
                       cipher_info = CipherInfo#cipher_info{
                                       decode_iv=Iv,
                                       stream_dec_state=StreamState}},
            ?MODULE:'R_TARGET_INFO'(cast, {client, Rest}, State1)
    end;
'R_IVEC'(info, Msg, StateData) ->
    handle_info(Msg, 'R_IVEC', StateData).

'R_TARGET_INFO'(cast, {client, Data}, #state{ buf = Buffer,
                                              cipher_info=CipherInfo}=State) ->
    {NewCipherInfo, Data1} = shadowsocks_crypt:decode(CipherInfo, Data),
    case decode_target_info(Data1) of
        incomplete ->
            {next_state, 'R_TARGET_INFO',
             State#state{buf= <<Buffer/binary, Data1/binary>>,
                        cipher_info = NewCipherInfo}, ?TIMEOUT};
        {error, _, _} = Error ->
            {stop, Error, State};
        {TargetAddr, TargetPort, Rest} ->
            case gen_tcp:connect(TargetAddr, TargetPort,
                                 [{active, once}, {packet, raw}, binary]) of
                {ok, SocketRemote} ->
                    ?INFO("Connected to remote ~p:~p\n", [ TargetAddr, TargetPort]),
                    gen_tcp:send(SocketRemote, Rest),
                    {next_state, 'R_DATA',
                     State#state{buf= <<>>, socket_remote=SocketRemote,
                                 remote_addr={TargetAddr, TargetPort},
                                 cipher_info = NewCipherInfo},
                     ?TIMEOUT};
                {error, Reason} ->
                    ?ERROR("Can not connect to remote ~p:~p, ~p\n",
                           [ TargetAddr, TargetPort, Reason]),
                    {stop, Reason, State}
            end
    end;
'R_TARGET_INFO'(info, Msg, StateData) ->
    handle_info(Msg, 'R_TARGET_INFO', StateData).

'L_IVEC'(cast, {client, Data}, #state{
                  socket_remote = SocketRemote,
                  cipher_info =#cipher_info{decode_iv=undefined}=CipherInfo}
                =State) ->
    {NewCipherInfo,EncData} = shadowsocks_crypt:encode(CipherInfo, Data),
    gen_tcp:send(SocketRemote, EncData),
    {next_state, 'L_IVEC', State#state{cipher_info=NewCipherInfo}};
'L_IVEC'(cast, {remote, Data}, #state{
                  cipher_info=#cipher_info{method=Method, key=Key, decode_iv=undefined}
                  =CipherInfo} = State) ->
    Buffer = <<(State#state.buf)/binary, Data/binary>>,
    {_, IvLen} = shadowsocks_crypt:key_iv_len(Method),
    case decode_ivec(Buffer, IvLen) of
        incomplete ->
            {next_state, 'L_IVEC',
             State#state{buf=Buffer}, ?TIMEOUT};
        {Iv, Rest} ->
            StreamState = shadowsocks_crypt:stream_init(Method, Key, Iv),
            State1 = State#state{buf = <<>>, cipher_info =
                                     CipherInfo#cipher_info{
                                       decode_iv=Iv,
                                       stream_dec_state=StreamState}},
            ?MODULE:'L_DATA'(cast, {remote, Rest}, State1)
    end;
'L_IVEC'(info, Msg, StateData) ->
    handle_info(Msg, 'L_IVEC', StateData).

'L_DATA'(cast, {client, Data}, #state{socket_remote=SocketRemote,
                                       cipher_info=CipherInfo} = State) ->
    {NewCipherInfo,EncData} = shadowsocks_crypt:encode(CipherInfo, Data),
    gen_tcp:send(SocketRemote, EncData),
    {next_state, 'L_DATA', State#state{cipher_info=NewCipherInfo}};
'L_DATA'(cast, {remote, EncData}, #state{socket_client=SocketClient,
                                          cipher_info=CipherInfo} = State) ->
    {NewCipherInfo, Data} = shadowsocks_crypt:decode(CipherInfo, EncData),
    gen_tcp:send(SocketClient, Data),
    {next_state, 'L_DATA', State#state{cipher_info=NewCipherInfo}};
'L_DATA'(timeout, _, State) ->
    {stop, normal, State};
'L_DATA'(cast, Data, State) ->
    ?WARNING("Ignoring data: ~p\n", [Data]),
    {next_state, 'L_DATA', State};
'L_DATA'(info, Msg, StateData) ->
    handle_info(Msg, 'L_DATA', StateData).

'R_DATA'(cast, {client, EncData}, #state{ socket_remote=SocketRemote,
                                          cipher_info=CipherInfo} = State) ->
    {NewCipherInfo, DecData} = shadowsocks_crypt:decode(CipherInfo, EncData),
    gen_tcp:send(SocketRemote, DecData),
    {next_state, 'R_DATA', State#state{cipher_info=NewCipherInfo}};
'R_DATA'(cast, {remote, Data}, #state{ socket_client=SocketClient,
                                       cipher_info=CipherInfo} = State) ->
    {NewCipherInfo, EncData} = shadowsocks_crypt:encode(CipherInfo, Data),
    gen_tcp:send(SocketClient, EncData),
    {next_state, 'R_DATA', State#state{cipher_info=NewCipherInfo}};
'R_DATA'(cast, Data, State) ->
    ?WARNING("Ignoring data: ~p\n", [Data]),
    {next_state, 'R_DATA', State};
'R_DATA'(timeout, _, State) ->
    {stop, normal, State};
'R_DATA'(info, Msg, StateData) ->
    handle_info(Msg, 'R_DATA', StateData).

%%%===================================================================
%%% Internal functions
%%%===================================================================
decode_socks5_auth(<<Ver:8/big, _/binary>>) when Ver =/= ?SOCKS5_VER ->
    {error, not_supported_version, Ver};
decode_socks5_auth(<<?SOCKS5_VER:8/big, NMethods:8/big,
                     Methods:NMethods/binary, Rest/binary>>) ->
    {?SOCKS5_VER, NMethods, Methods, Rest};
decode_socks5_auth(_) ->
    incomplete.

decode_socks5_req(<<Ver:8/big, _/binary>>)
  when Ver =/= ?SOCKS5_VER ->
    {error, not_supported_version, Ver};
decode_socks5_req(<<_:8/big, Cmd:8/big, _/binary>>)
  when Cmd =/= ?SOCKS5_REQ_CONNECT ->
    {error, not_supported_command, Cmd};
decode_socks5_req(<<_:3/binary, AddrType:8/big, _Rest/binary>>)
  when AddrType =/= ?SOCKS5_ATYP_V4,
       AddrType =/= ?SOCKS5_ATYP_DOM,
       AddrType =/= ?SOCKS5_ATYP_V6 ->
    {error, not_supported_address_type, AddrType};
decode_socks5_req(<<?SOCKS5_VER:8/big, ?SOCKS5_REQ_CONNECT:8/big, _:8/big,
                     ?SOCKS5_ATYP_V4:8/big,
                     DestAddr:4/binary, DestPort:16/big, Rest/binary>>) ->
    {?SOCKS5_VER, ?SOCKS5_ATYP_V4, list_to_tuple(binary_to_list(DestAddr)),
     DestPort, Rest};
decode_socks5_req(<<?SOCKS5_VER:8/big, ?SOCKS5_REQ_CONNECT:8/big, _:8/big,
                     ?SOCKS5_ATYP_DOM:8/big, DomLen:8/big,
                     Domain:DomLen/binary, DestPort:16/big,
                     Rest/binary>>) ->
    {?SOCKS5_VER, ?SOCKS5_ATYP_DOM, binary_to_list(Domain), DestPort, Rest};
decode_socks5_req(<<?SOCKS5_VER:8/big, ?SOCKS5_REQ_CONNECT:8/big, _:8/big,
                     ?SOCKS5_ATYP_V6:8/big,
                     _DestAddr: 8/binary-unit:16, DestPort:16/big, Rest/binary>>) ->
                     DestAddr = [binary:decode_unsigned(U, big) || <<U:1/binary-unit:16>> <= _DestAddr],
    {?SOCKS5_VER, ?SOCKS5_ATYP_V6, list_to_tuple(DestAddr),
     DestPort, Rest};
decode_socks5_req(_) ->
    incomplete.

decode_target_info(<<AddrType:8/big, _/binary>>)
  when AddrType =/= ?SOCKS5_ATYP_V4,
       AddrType =/= ?SOCKS5_ATYP_DOM,
       AddrType =/= ?SOCKS5_ATYP_V6 ->
    {error, not_supported_address_type, AddrType};
decode_target_info(<<?SOCKS5_ATYP_V4:8/big, DestAddr:4/binary, DestPort:16/big,
                     Rest/binary>>) ->
    {list_to_tuple(binary_to_list(DestAddr)), DestPort, Rest};
decode_target_info(<<?SOCKS5_ATYP_DOM:8/big, DomLen:8/big, Domain:DomLen/binary,
                     DestPort:16/big, Rest/binary>>) ->
                     case inet:getaddr(binary_to_list(Domain), inet6) of
                         {ok, Addr} -> { Addr, DestPort, Rest};
                         {error, _} -> { binary_to_list(Domain), DestPort, Rest}
                     end;
decode_target_info(<<?SOCKS5_ATYP_V6:8/big, _DestAddr:8/binary-unit:16, DestPort:16/big,
                     Rest/binary>>) ->
                     DestAddr = [binary:decode_unsigned(U, big) || <<U:1/binary-unit:16>> <= _DestAddr],
    {list_to_tuple(DestAddr), DestPort, Rest};
decode_target_info(_) ->
    incomplete.

decode_ivec(Data, IvLen) ->
    case Data of
        <<Iv:IvLen/binary, Rest/binary>> -> {Iv,Rest};
        _ -> incomplete
    end.

handle_info({tcp, SocketClient, Bin}, StateName,
            #state{socket_client=SocketClient} = StateData) ->
    inet:setopts(SocketClient, [{active, once}]),
    ?MODULE:StateName(cast, {client, Bin}, StateData);
handle_info({tcp_closed, SocketClient}, _StateName,
            #state{socket_client=SocketClient, client_addr=Addr,
                   remote_addr=RemoteAddr} = StateData) ->
    ?INFO("Client ~p disconnected(for ~p).\n", [Addr, RemoteAddr]),
    {stop, normal, StateData};
handle_info({tcp, SocketRemote, Bin}, StateName,
            #state{socket_remote=SocketRemote} = StateData) ->
    inet:setopts(SocketRemote, [{active, once}]),
    ?MODULE:StateName(cast, {remote, Bin}, StateData);
handle_info({tcp_closed, SocketRemote}, _StateName,
            #state{socket_remote=SocketRemote, remote_addr=Addr} = StateData) ->
    ?INFO("Remote ~p disconnected.\n", [Addr]),
    {stop, normal, StateData};
handle_info(_Info, StateName, State) ->
    {next_state, StateName, State}.
