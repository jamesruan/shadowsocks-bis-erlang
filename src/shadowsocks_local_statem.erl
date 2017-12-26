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
-module(shadowsocks_local_statem).

-behaviour(gen_statem).

%% gen_statem callbacks
-export([callback_mode/0, init/1]).

%% API
-export([start_link/1, set_socket/2]).

%% state functions
-export(['WAIT_FOR_SOCKET'/3,
         'WAIT_FOR_SOCKS5_AUTH'/3,
         'WAIT_FOR_SOCKS5_REQUEST'/3,
         'WAIT_FOR_IVEC'/3,
         'WAIT_FOR_DATA'/3]).

-include("shadowsocks.hrl").

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
    {ok, 'WAIT_FOR_SOCKET', #lstate{remote_addr = {ServerAddr, ServerPort},
                                    cipher_info = CipherInfo}}.

%%%===================================================================
%%% state functions
%%%===================================================================
%%  WAIT_FOR_SOCKET -> WAIT_FOR_SOCKS5_AUTH -> WAIT_FOR_SOCKS5_REQUEST ->
%%  WAIT_FOR_IVEC -> WAIT_FOR_DATA <-> WAIT_FOR_DATA


'WAIT_FOR_SOCKET'(cast, {socket_ready, Socket}, State) ->
    inet:setopts(Socket, [{active, once}, {packet, raw}, binary]),
    {ok, Addr} = inet:peername(Socket),
    {next_state, 'WAIT_FOR_SOCKS5_AUTH',
     State#lstate{socket_client=Socket, client_addr=Addr}, ?TIMEOUT};
'WAIT_FOR_SOCKET'(cast, Other, State) ->
    ?ERROR("Unexpected message: ~p\n", [Other]),
    %% Allow to receive async messages
    {next_state, 'WAIT_FOR_SOCKET', State};
'WAIT_FOR_SOCKET'({info, Msg}, StateName, StateData) ->
    handle_info(Msg, StateName, StateData).

'WAIT_FOR_SOCKS5_AUTH'(cast, {client, Data}, #lstate{socket_client=S} = State) ->
    Buffer = <<(State#lstate.buf)/binary, Data/binary>>,
    case decode_socks5_auth(Buffer) of
        incomplete ->
            {next_state, 'WAIT_FOR_SOCKS5_AUTH',
             State#lstate{buf=Buffer}, ?TIMEOUT};
        {?SOCKS5_VER, _, _, Rest}->
            gen_tcp:send(S, <<?SOCKS5_VER, ?SOCKS5_AUTH_NONE>>),
            {next_state, 'WAIT_FOR_SOCKS5_REQUEST',
             State#lstate{buf=Rest}, ?TIMEOUT};
        Error ->
            ?ERROR("'WAIT_FOR_SOCKS5_AUTH' with error: ~p\n", [Error]),
            {stop, Error, State}
    end;
'WAIT_FOR_SOCKS5_AUTH'(cast, timeout, #lstate{client_addr=Addr}=State) ->
    ?ERROR("Client connection timeout: 'WAIT_FOR_SOCKS5_AUTH', ~p\n",
           [Addr]),
    {stop, normal, State};
'WAIT_FOR_SOCKS5_AUTH'({info, Msg}, StateName, StateData) ->
    handle_info(Msg, StateName, StateData).

'WAIT_FOR_SOCKS5_REQUEST'(cast, {client, Data}, #lstate{
                            socket_client=S, remote_addr={RemoteHost, RemotePort},
                            cipher_info=CipherInfo } = State) ->
    Buffer = <<(State#lstate.buf)/binary, Data/binary>>,
    case decode_socks5_req(Buffer) of
        incomplete ->
            {next_state, 'WAIT_FOR_SOCKS5_REQUEST',
             State#lstate{buf=Buffer}, ?TIMEOUT};
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
                {ok, RemoteSocket} ->
                    ?INFO("Connected to remote ~p:~p for proxying ~p:~p\n",
                          [RemoteHost, RemotePort, Addr, Port]),
                    gen_tcp:send(RemoteSocket, EncodedTargert),
                    gen_tcp:send(RemoteSocket, Rest),
                    {next_state, 'WAIT_FOR_IVEC',
                     State#lstate{buf= <<>>, socket_remote=RemoteSocket,
                                 cipher_info = NewCipherInfo}, ?TIMEOUT};
                {error, Reason} ->
                    ?ERROR("'WAIT_FOR_SOCKS5_REQUEST' with error: ~p\n", [Reason]),
                    {stop, Reason, State}
            end;
        Error ->
            ?ERROR("'WAIT_FOR_SOCKS5_REQUEST' with error: ~p\n", [Error]),
            {stop, Error, State}
    end;
'WAIT_FOR_SOCKS5_REQUEST'(cast, timeout, #lstate{client_addr=Addr}=State) ->
    ?ERROR("Client connection timeout: 'WAIT_FOR_SOCKS5_REQUEST', ~p\n",
           [Addr]),
    {stop, normal, State};
'WAIT_FOR_SOCKS5_REQUEST'({info, Msg}, StateName, StateData) ->
    handle_info(Msg, StateName, StateData).

'WAIT_FOR_IVEC'(cast, {client, Data}, #lstate{
                  socket_remote = RemoteSocket,
                  cipher_info =#cipher_info{decode_iv=undefined}=CipherInfo}
                =State) ->
    {NewCipherInfo,EncData} = shadowsocks_crypt:encode(CipherInfo, Data),
    gen_tcp:send(RemoteSocket, EncData),
    {next_state, 'WAIT_FOR_IVEC', State#lstate{cipher_info=NewCipherInfo}};
'WAIT_FOR_IVEC'(cast, {remote, Data}, #lstate{
                  cipher_info=#cipher_info{method=Method, key=Key, decode_iv=undefined}
                  =CipherInfo} = State) ->
    Buffer = <<(State#lstate.buf)/binary, Data/binary>>,
    {_, IvLen} = shadowsocks_crypt:key_iv_len(Method),
    case decode_ivec(Buffer, IvLen) of
        incomplete ->
            {next_state, 'WAIT_FOR_IVEC',
             State#lstate{buf=Buffer}, ?TIMEOUT};
        {Iv, Rest} ->
            StreamState = shadowsocks_crypt:stream_init(Method, Key, Iv),
            State1 = State#lstate{buf = <<>>, cipher_info =
                                     CipherInfo#cipher_info{
                                       decode_iv=Iv,
                                       stream_dec_state=StreamState}},
            ?MODULE:'WAIT_FOR_DATA'({remote, Rest}, State1)
    end;
'WAIT_FOR_IVEC'({info, Msg}, StateName, StateData) ->
    handle_info(Msg, StateName, StateData).

'WAIT_FOR_DATA'(cast, {client, Data}, #lstate{socket_remote=RemoteSocket,
                                       cipher_info=CipherInfo} = State) ->
    {NewCipherInfo,EncData} = shadowsocks_crypt:encode(CipherInfo, Data),
    gen_tcp:send(RemoteSocket, EncData),
    {next_state, 'WAIT_FOR_DATA', State#lstate{cipher_info=NewCipherInfo}};
'WAIT_FOR_DATA'(cast, {remote, EncData}, #lstate{socket_client=ClientSocket,
                                          cipher_info=CipherInfo} = State) ->
    {NewCipherInfo, Data} = shadowsocks_crypt:decode(CipherInfo, EncData),
    gen_tcp:send(ClientSocket, Data),
    {next_state, 'WAIT_FOR_DATA', State#lstate{cipher_info=NewCipherInfo}};
'WAIT_FOR_DATA'(cast, timeout, State) ->
    {stop, normal, State};
'WAIT_FOR_DATA'(cast, Data, State) ->
    ?WARNING("Ignoring data: ~p\n", [Data]),
    {next_state, 'WAIT_FOR_DATA', State};
'WAIT_FOR_DATA'({info, Msg}, StateName, StateData) ->
    handle_info(Msg, StateName, StateData).

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

decode_ivec(Data, IvLen) ->
    case Data of
        <<Iv:IvLen/binary, Rest/binary>> -> {Iv,Rest};
        _ -> incomplete
    end.

handle_info({tcp, ClientSocket, Bin}, StateName,
            #lstate{socket_client=ClientSocket} = StateData) ->
    inet:setopts(ClientSocket, [{active, once}]),
    ?MODULE:StateName({client, Bin}, StateData);
handle_info({tcp_closed, ClientSocket}, _StateName,
            #lstate{socket_client=ClientSocket, client_addr=Addr,
                   remote_addr=RemoteAddr} = StateData) ->
    ?INFO("Client ~p disconnected(for ~p).\n", [Addr, RemoteAddr]),
    {stop, normal, StateData};
handle_info({tcp, RemoteSocket, Bin}, StateName,
            #lstate{socket_remote=RemoteSocket} = StateData) ->
    inet:setopts(RemoteSocket, [{active, once}]),
    ?MODULE:StateName({remote, Bin}, StateData);
handle_info({tcp_closed, RemoteSocket}, _StateName,
            #lstate{socket_remote=RemoteSocket, remote_addr=Addr} = StateData) ->
    ?INFO("Remote ~p disconnected.\n", [Addr]),
    {stop, normal, StateData};
handle_info(_Info, StateName, State) ->
    {next_state, StateName, State}.
