-module(set1).
-author("Martin Schut <martin-github@wommm.nl>").

-export([all/0, challenge/1]).

all() -> lists:seq(1,3).

challenge(1) ->
  io:fwrite("Convert hex to base64~n"),

  Input = <<"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d">>,
  Expected = <<"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t">>,

  BitString = cryptopals_bitsequence:bitstring_from_hex(Input),
  Base64 = cryptopals_bitsequence:base64_from_bitstring(BitString),

  #{input => Input, output => Base64, expectation => Expected};

challenge(2) ->
  io:fwrite("Fixed XOR~n"),

  Input1 = <<"1c0111001f010100061a024b53535009181c">>,
  Input2 = <<"686974207468652062756c6c277320657965">>,
  Expected = <<"746865206b696420646f6e277420706c6179">>,

  BitString1 = cryptopals_bitsequence:bitstring_from_hex(Input1),
  BitString2 = cryptopals_bitsequence:bitstring_from_hex(Input2),
  XorredBitString = cryptopals_bitsequence:bitstring_xor(BitString2, BitString1),
  HexString = cryptopals_bitsequence:hex_from_bitstring(XorredBitString),

  #{input => io_lib:format("~s XOR ~s", [Input1, Input2]), output => HexString, expectation => Expected};

challenge(3) ->
  io:fwrite("Single-byte XOR cipher~n"),

  Input = <<"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736">>,

  BitString = cryptopals_bitsequence:bitstring_from_hex(Input),
  Keys = lists:seq(0, 255),
  PlainTexts = [cryptopals_bitsequence:bitstring_xor(BitString, <<Key>>) || Key <- Keys],
  GoodnessOfFit = [cryptopals_analysis:goodness_of_fit(PlainText, "EN") || PlainText <- PlainTexts],
  BestFit = lists:min(GoodnessOfFit),
  ResultTuples = lists:zip3(Keys, GoodnessOfFit, PlainTexts),
  Winner = lists:any(fun({_Key, Fit, _PlainText}) -> Fit =:= BestFit end, ResultTuples),

  #{input => Input, output => Winner};

challenge(4) ->
  true.
