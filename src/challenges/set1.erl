-module(set1).
-author("Martin Schut <martin-github@wommm.nl>").

-export([
  all/0,
  convert_hex_to_base64/0,
  fixed_xor/0,
  single_byte_xor/0,
  detect_single_character_xor/0,
  repeating_key_xor/0]).

all() ->
  [
    convert_hex_to_base64,
    {"Fixed XOR", fixed_xor},
    {"Single-byte XOR cipher", single_byte_xor},
    {"Detect single-character XOR", detect_single_character_xor},
    {"Implement repeating-key XOR", repeating_key_xor}
  ].

convert_hex_to_base64() ->
  Input = <<"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d">>,
  Expected = <<"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t">>,

  BitString = cryptopals_bitsequence:bitstring_from_hex(Input),
  Base64 = cryptopals_bitsequence:base64_from_bitstring(BitString),

  #{input => Input,
    output => Base64,
    expectation => Expected}.

fixed_xor() ->
  Input1 = <<"1c0111001f010100061a024b53535009181c">>,
  Input2 = <<"686974207468652062756c6c277320657965">>,
  Expected = <<"746865206b696420646f6e277420706c6179">>,

  BitString1 = cryptopals_bitsequence:bitstring_from_hex(Input1),
  BitString2 = cryptopals_bitsequence:bitstring_from_hex(Input2),
  XorredBitString = cryptopals_bitsequence:bitstring_xor(BitString2, BitString1),
  HexString = cryptopals_bitsequence:hex_from_bitstring(XorredBitString),

  #{input => io_lib:format("~s XOR ~s", [Input1, Input2]),
    output => HexString,
    expectation => Expected}.

single_byte_xor() ->
  Input = <<"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736">>,

  BitString = cryptopals_bitsequence:bitstring_from_hex(Input),
  Winner = cryptopals_analysis:guess_single_byte_xor(BitString, "EN"),
  {Key, _GoodnessOfFit, PlainText} = Winner,

  #{input => Input,
    output => io_lib:format("key '~p' results in ~p", [Key, PlainText])}.

detect_single_character_xor() ->
  InputFile = "./data/4.txt",

  {ok, Device} = file:open(InputFile, [read]),
  Guesses = cryptopals_file:map(fun(Line) ->
    HexString = list_to_bitstring(Line),
    BitString = cryptopals_bitsequence:bitstring_from_hex(HexString),
    Guess = cryptopals_analysis:guess_single_byte_xor(BitString, "EN"),
    erlang:append_element(Guess, HexString)
  end, Device),
  file:close(Device),

  Min = fun({_, FitA, _, _} = A, {_, FitB, _, _} = _B) when FitA < FitB -> A;
    (_A, B) -> B
  end,
  Result = lists:foldl(Min, hd(Guesses), tl(Guesses)),
  {Key, _Fit, PlainText, CipherText} = Result,

  #{input => io_lib:format("from file '~s'", [InputFile]),
    output => io_lib:format("key '~p' results in ~p for cipher <<~s>>", [Key, PlainText, CipherText])}.

repeating_key_xor() ->
  PlainText = <<"Burning 'em, if you ain't quick and nimble", 10, "I go crazy when I hear a cymbal">>,
  Key = <<"ICE">>,
  Expected = <<"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f">>,

  XorredBitString = cryptopals_bitsequence:bitstring_xor(PlainText, Key),
  HexString = cryptopals_bitsequence:hex_from_bitstring(XorredBitString),

  #{input => io_lib:format("~p XOR ~p", [PlainText, Key]),
    output => HexString,
    expectation => Expected}.