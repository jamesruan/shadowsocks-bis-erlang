%%% @author Yongke <wangyongke@gmail.com>, James Ruan <ruanbeihong@gmail.com>
%%% @copyright (C) 2014, Yongke, James Ruan
%%% @doc
%%% APIs for encrypt and decrypt
%%% @end

-module(shadowsocks_crypt).

%% API
-export([init_cipher_info/2, encode/2, decode/2, key_iv_len/1, stream_init/3]).

-include("shadowsocks.hrl").

%%--------------------------------------------------------------------
%% @doc
%% Return the cipher information
%% 
%% @spec cipher_info(Method, Password::string()) -> 
%%                       {Method, Key::binary(), IvEnc::binary(), IvDec::binanry()}
%%      Method := rc4 | des_cfb
%% @end
%%--------------------------------------------------------------------
init_cipher_info(Method, Password) ->
    {KeyLen, IvLen} = key_iv_len(Method),
    {Key, Iv} = evp_bytestokey(md5, Password, KeyLen, IvLen),
    #cipher_info{method=Method, key=Key, encode_iv=Iv, decode_iv=undefined,
                stream_enc_state = stream_init(Method, Key, Iv),
                stream_dec_state = stream_init(Method, Key, Iv)}.

%%--------------------------------------------------------------------
%% @doc 
%% Encode function
%% @spec encode(CipherInfo, Data) -> Data
%%      CipherInfo := cipher_info()
%%      Data := iolist() | binary()
%% @end
%%--------------------------------------------------------------------
encode(#cipher_info{iv_sent = false, encode_iv=Iv}=CipherInfo, Data) ->
    NewCipherInfo = CipherInfo#cipher_info{iv_sent=true},
    {NewCipherInfo1, EncData} = encode(NewCipherInfo, Data), 
    {NewCipherInfo1, <<Iv/binary, EncData/binary>>};
encode(#cipher_info{method=rc4, stream_enc_state=S}=CipherInfo, Data) ->
    {S1, EncData} = crypto:stream_encrypt(S, Data),
    {CipherInfo#cipher_info{stream_enc_state=S1}, EncData};
encode(#cipher_info{method=des_cfb, key=Key, encode_iv=Iv}=CipherInfo, Data) ->
    EncData = crypto:block_encrypt(des_cfb, Key, Iv, Data),
    NextIv = crypto:next_iv(des_cfb, EncData, Iv),
    {CipherInfo#cipher_info{encode_iv=NextIv}, EncData}.

%%--------------------------------------------------------------------
%% @doc 
%% Decode function
%% @spec decode(CipherInfo, Data) -> Data
%%                    {Method, Key::binary(), Iv::binary()}
%%      Method := rc4 | des_cfb
%%      Data := iolist() | binary()
%% @end
%%--------------------------------------------------------------------
decode(#cipher_info{method=rc4, stream_dec_state=S}=CipherInfo, EncData) ->
    {S1, Data} = crypto:stream_decrypt(S, EncData),
    {CipherInfo#cipher_info{stream_dec_state=S1}, Data};
decode(#cipher_info{method=des_cfb, key=Key, decode_iv=Iv}=CipherInfo, EncData) ->
    Data = crypto:block_decrypt(des_cfb, Key, Iv, EncData),
    NextIv = crypto:next_iv(des_cfb, Data, Iv),
    {CipherInfo#cipher_info{decode_iv=NextIv}, Data}.

%%--------------------------------------------------------------------
%% @doc 
%% Creates a key and an IV for doing encryption, from a password, 
%% using a hashing function.
%% @spec evp_bytestokey(HashMethod::hash_method(), Password::string(), 
%%                      KeyLen::integer(), IvLen::integer()) ->
%%      {Key::binary(), Iv::binary()}
%% @end
%%--------------------------------------------------------------------
evp_bytestokey(md5, Password, KeyLen, IvLen) ->
    evp_bytestokey_aux(md5, list_to_binary(Password), KeyLen, IvLen, <<>>).

evp_bytestokey_aux(md5, _, KeyLen, IvLen, Acc) 
  when KeyLen =< size(Acc) ->
    <<Key:KeyLen/binary, _/binary>> = Acc,
	%hashed key and randomized Iv
	Iv = crypto:rand_bytes(IvLen),
    {Key, Iv};
evp_bytestokey_aux(md5, Password, KeyLen, IvLen, Acc) ->
	%accumulate to arbitrary length
    Digest = crypto:hash(md5, <<Acc/binary, Password/binary>>),
    NewAcc = <<Acc/binary, Digest/binary>>,
    evp_bytestokey_aux(md5, Password, KeyLen, IvLen, NewAcc).

key_iv_len(des_cfb) ->
    {8, 8};
key_iv_len(rc4) ->
    {16, 16}.

stream_init(rc4, Key, Iv) ->
	Keymix = binary:list_to_bin([U bxor V || {U, V} <- lists:zip(binary:bin_to_list(Key), binary:bin_to_list(Iv))]),
    S = crypto:stream_init(rc4, Keymix),
	%discard first 1024 bit against attack of http://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack
	{S1, _} = crypto:stream_encrypt( S, <<0:(1024*8)>>),
	S1;
stream_init(_, _, _) ->
    undefined.
