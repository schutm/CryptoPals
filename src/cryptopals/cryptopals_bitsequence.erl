-module(cryptopals_bitsequence).
-author("Martin Schut <martin-github@wommm.nl").

-define(BITS_PER_BYTE, 8).

%%
%% API
%%
-export([
  base64_from_bitstring/1,
  bitstring_from_base64/1,
  bitstring_foldl/3,
  bitstring_from_hex/1,
  bitstring_partition/2,
  bitstring_unzip/2,
  bitstring_uppercase/1,
  bitstring_xor/2,
  contains_any/2,
  hex_from_bitstring/1]).

base64_from_bitstring(BitString) ->
  Bytes = 3*(byte_size(BitString) div 3),
  <<Triplets:Bytes/binary,Rest/binary>> = BitString,
  Base64BitString = << <<(encode_base64(A)):8>> || <<A:6>> <= Triplets >>,
  case Rest of
    <<A:6,B:6,C:4>> ->
      <<Base64BitString/binary, (encode_base64(A)):8, (encode_base64(B)):8, (encode_base64(C bsl 2)):8, $=:8>>;
    <<A:6,B:2>> ->
      <<Base64BitString/binary, (encode_base64(A)):8, (encode_base64(B bsl 4)):8, $=:8, $=:8>>;
    <<>> ->
      Base64BitString
  end.

bitstring_from_base64(Base64BitString) ->
  Base64WithoutWhitespace = remove_whitespace(Base64BitString),
  DecodedBits = << <<(decode_base64(Character))/bits>> || <<Character:8>> <= Base64WithoutWhitespace >>,
  Base64Bytes = byte_size(Base64WithoutWhitespace) - 2,
  case Base64WithoutWhitespace of
    <<_:Base64Bytes/bytes, $=, $=>> -> OverflowBits = 4;
    <<_:Base64Bytes/bytes, _, $=>>  -> OverflowBits = 2;
    <<_:Base64Bytes/bytes, _, _>>   -> OverflowBits = 0
  end,
  Bits = bit_size(DecodedBits) - OverflowBits,
  <<BitString:Bits/bitstring, _:OverflowBits>> = DecodedBits,
  BitString.

bitstring_foldl(Fun, BitString, Acc) ->
  bitstring_foldl_acc(Fun, BitString, Acc).

bitstring_partition(BitString, Bytes) ->
  bitstring_partition_acc(BitString, Bytes * ?BITS_PER_BYTE, []).

bitstring_unzip(BitString, Partitions) ->
  Acc = cryptopals_utils:for(fun(_I) -> <<>> end, 1, Partitions),
  bitstring_unzip_acc(BitString, 0, Acc).

bitstring_uppercase(Text) ->
  bitstring_uppercase_acc(Text, <<>>).

bitstring_xor(Text, Key) ->
  bitstring_xor_acc(Text, Key, <<>>).

contains_any(Sequence, ListOfBits) ->
  lists:any(fun(Bits) -> contains(Sequence, Bits) end, ListOfBits).

hex_from_bitstring(BitString) ->
  HexList = [integer_to_hex(B) || <<B:4>> <= BitString],
  HexBitString = list_to_bitstring(HexList),
  HexBitString.

bitstring_from_hex(HexString) ->
  List = [list_to_integer([B1, B2], 16) || <<B1, B2>> <= HexString],
  BitString = list_to_bitstring(List),
  BitString.


%%
%% Internal functions
%%
remove_whitespace(BitString) ->
  remove_whitespace_acc(BitString, <<>>).

remove_whitespace_acc(<<>>, Acc) ->
  Acc;
remove_whitespace_acc(<<Byte:8/bitstring, Rest/bitstring>>, Acc) when Byte =:= <<10>> -> % ; Byte =:= 13; Byte =:= 32 ->
  remove_whitespace_acc(Rest, Acc);
remove_whitespace_acc(<<Byte:8/bitstring, Rest/bitstring>>, Acc) ->
  remove_whitespace_acc(Rest, <<Acc/bitstring, Byte/bitstring>>).

bitstring_foldl_acc(_Fun, <<>>, Acc) ->
  Acc;
bitstring_foldl_acc(Fun, <<Bit:1, Rest/bitstring>>, Acc) ->
  bitstring_foldl_acc(Fun, Rest, Fun(Bit, Acc)).

bitstring_partition_acc(BitString, Bits, Acc) ->
  case bit_size(BitString) =< Bits of
    true ->
      [BitString|Acc];
    false ->
      <<Partition:Bits/bitstring, Rest/bitstring>> = BitString,
      bitstring_partition_acc(Rest, Bits, [Partition|Acc])
  end.

bitstring_uppercase_acc(<<>>, Acc) ->
  Acc;
bitstring_uppercase_acc(<<Character:8, Rest/bitstring>>, Acc) ->
  if
    Character >= $a andalso Character =< $z ->
      bitstring_uppercase_acc(Rest, <<Acc/bitstring, (Character + ($A - $a))>>);
    true ->
      bitstring_uppercase_acc(Rest, <<Acc/bitstring, Character>>)
  end.

bitstring_unzip_acc(<<>>, 0, Acc) ->
  Acc;
bitstring_unzip_acc(<<>>, Block, Acc = [Head|Tail]) ->
  bitstring_unzip_acc(<<>>, (Block + 1) rem length(Acc), Tail ++ [Head]);
bitstring_unzip_acc(<<Character:8/bitstring, Rest/bitstring>>, Block, Acc = [Head|Tail]) ->
  bitstring_unzip_acc(Rest, (Block + 1) rem length(Acc), Tail ++ [<<Head/bitstring, Character/bitstring>>]).

bitstring_xor_acc(<<>>, _Key, Acc) ->
  Acc;
bitstring_xor_acc(Text, Key, Acc) ->
  TextBitSize = bit_size(Text),
  KeyBitSize = bit_size(Key),
  BitSize = min(TextBitSize, KeyBitSize),

  <<TextBits:BitSize, RestTextBits/bitstring>> = Text,
  <<KeyBits:BitSize, _RestKeyBits/bitstring>> = Key,

  CipherTextBits = <<(TextBits bxor KeyBits):BitSize>>,
  bitstring_xor_acc(RestTextBits, Key, <<Acc/bitstring, CipherTextBits/bitstring>>).

contains(<<>>, _Bits) -> false;
contains(Sequence, Bits) ->
  BitSize = bit_size(Bits),
  <<SequenceBits:BitSize/bitstring, Rest/bitstring>> = Sequence,
  case SequenceBits of
    Bits -> true;
    _    -> contains(Rest, Bits)
  end.

encode_base64(Value) when Value >= 0, Value =< 25 -> $A + Value;
encode_base64(Value) when Value >= 26, Value =< 51 -> $a + Value - 26;
encode_base64(Value) when Value >= 52, Value =< 61 -> $0 + Value - 52;
encode_base64(Value) when Value =:= 62 -> $+;
encode_base64(Value) when Value =:= 63 -> $/.

decode_base64(Character) when Character >= $A, Character =< $Z -> <<(Character - $A):6>>;
decode_base64(Character) when Character >= $a, Character =< $z -> <<(Character - $a + 26):6>>;
decode_base64(Character) when Character >= $0, Character =< $9 -> <<(Character - $0 + 52):6>>;
decode_base64(Character) when Character =:= $+ -> <<62:6>>;
decode_base64(Character) when Character =:= $/ -> <<63:6>>;
decode_base64(Character) when Character =:= $= -> <<>>.

integer_to_hex(Integer) when Integer >= 0, Integer =< 9 -> $0 + Integer;
integer_to_hex(Integer) when Integer >= 10, Integer =< 15 -> $a + Integer - 10.
