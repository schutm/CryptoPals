-module(cryptopals_bitsequence).
-author("Martin Schut <martin-github@wommm.nl").

%%
%% API
%%
-export([base64_from_bitstring/1, contains_any/2, bitstring_uppercase/1, bitstring_from_hex/1, bitstring_xor/2, hex_from_bitstring/1]).

bitstring_uppercase(Text) ->
  bitstring_uppercase_acc(Text, <<>>).

bitstring_xor(Text, Key) ->
  bitstring_xor_acc(Text, Key, <<>>).

contains_any(Sequence, ListOfBits) ->
  lists:any(fun(Bits) -> contains(Sequence, Bits) end, ListOfBits).

base64_from_bitstring(BitString) ->
  Base64List = [integer_to_base64(B) || <<B:6>> <= BitString],
  Base64BitString = list_to_bitstring(Base64List),
  Base64BitString.

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
bitstring_uppercase_acc(<<>>, Acc) ->
  Acc;
bitstring_uppercase_acc(Text, Acc) ->
  <<Character:8, Rest/bitstring>> = Text,
  if
    Character >= $a andalso Character =< $z ->
      bitstring_uppercase_acc(Rest, <<Acc/bitstring, (Character + ($A - $a))>>);
    true ->
      bitstring_uppercase_acc(Rest, <<Acc/bitstring, Character>>)
  end.

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

integer_to_base64(Integer) when Integer >= 0, Integer =< 25 -> $A + Integer;
integer_to_base64(Integer) when Integer >= 26, Integer =< 51 -> $a + Integer - 26;
integer_to_base64(Integer) when Integer >= 52, Integer =< 61 -> $0 + Integer - 52;
integer_to_base64(Integer) when Integer =:= 62 -> $+;
integer_to_base64(Integer) when Integer =:= 63 -> $/.

integer_to_hex(Integer) when Integer >= 0, Integer =< 9 -> $0 + Integer;
integer_to_hex(Integer) when Integer >= 10, Integer =< 15 -> $a + Integer - 10.
