-module(set1).
-author("Martin Schut <martin-github@wommm.nl>").

-export([
  all/0,
  convert_hex_to_base64/0,
  fixed_xor/0,
  single_byte_xor/0,
  detect_single_character_xor/0,
  implement_repeating_key_xor/0,
  break_repeating_key_xor/0,
  aes_in_ecb_mode/0,
  detect_aes_in_ecb_mode/0]).

all() ->
  [
    convert_hex_to_base64,
    {"Fixed XOR", fixed_xor},
    {"Single-byte XOR cipher", single_byte_xor},
    {"Detect single-character XOR", detect_single_character_xor},
    {"Implement repeating-key XOR", implement_repeating_key_xor},
    {"Break repeating-key XOR", break_repeating_key_xor},
    {"AES in ECB mode", aes_in_ecb_mode},
    {"Detect AES in ECB mode", detect_aes_in_ecb_mode}
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

  #{input => io_lib:format("~p XOR ~p", [Input1, Input2]),
    output => HexString,
    expectation => Expected}.

single_byte_xor() ->
  Input = <<"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736">>,

  CipherString = cryptopals_bitsequence:bitstring_from_hex(Input),
  {Key, _Fitness} = cryptopals_analysis:guess_single_byte_xor(CipherString, "EN"),
  PlainText = cryptopals_bitsequence:bitstring_xor(CipherString, Key),

  #{input => Input,
    output => io_lib:format("key ~p results in ~p", [Key, PlainText])}.

detect_single_character_xor() ->
  InputFile = "./data/4.txt",

  {ok, Device} = file:open(InputFile, [read]),
  Guesses = cryptopals_file:map(fun(Line) ->
    HexString = list_to_bitstring(Line),
    CipherString = cryptopals_bitsequence:bitstring_from_hex(HexString),
    Guess = cryptopals_analysis:guess_single_byte_xor(CipherString, "EN"),
    erlang:append_element(Guess, HexString)
  end, Device),
  file:close(Device),
  {Key, _Fitness, HexString} = cryptopals_lists:min(2, Guesses),

  CipherString = cryptopals_bitsequence:bitstring_from_hex(HexString),
  PlainText = cryptopals_bitsequence:bitstring_xor(CipherString, Key),
  #{input => io_lib:format("from file ~p", [InputFile]),
    output => io_lib:format("key ~p results in ~p for hexstring ~p", [Key, PlainText, HexString])}.

implement_repeating_key_xor() ->
  PlainText = <<"Burning 'em, if you ain't quick and nimble", 10, "I go crazy when I hear a cymbal">>,
  Key = <<"ICE">>,
  Expected = <<"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f">>,

  XorredBitString = cryptopals_bitsequence:bitstring_xor(PlainText, Key),
  HexString = cryptopals_bitsequence:hex_from_bitstring(XorredBitString),

  #{input => io_lib:format("~p XOR ~p", [PlainText, Key]),
    output => HexString,
    expectation => Expected}.

break_repeating_key_xor() ->
  InputFile = "./data/6.txt",

  {ok, Binary} = file:read_file(InputFile),
  CipherText = cryptopals_bitsequence:bitstring_from_base64(Binary),
  GuessedSize = cryptopals_analysis:guess_key_size(CipherText, lists:seq(2, 40)),
  Key = cryptopals_analysis:guess_multiple_byte_xor(CipherText, GuessedSize),
  PlainText = cryptopals_bitsequence:bitstring_xor(CipherText, Key),

  #{input => io_lib:format("from file '~p'", [InputFile]),
    output => io_lib:format("key ~p results in ~p", [Key, PlainText])}.

aes_in_ecb_mode() ->
  InputFile = "./data/7.txt",
  Key = <<"YELLOW SUBMARINE">>,

  {ok, Binary} = file:read_file(InputFile),
  CipherText = cryptopals_bitsequence:bitstring_from_base64(Binary),
  PlainText = cryptopals_crypto:decrypt(aes_ecb128, Key, CipherText),

  #{input => io_lib:format("from file '~p'", [InputFile]),
    output => PlainText}.

detect_aes_in_ecb_mode() ->
  InputFile = "./data/8.txt",

  {ok, Device} = file:open(InputFile, [read]),
  DifferentBlocks = cryptopals_file:map(fun(Line) ->
    HexString = list_to_bitstring(Line),
    CipherString = cryptopals_bitsequence:bitstring_from_hex(HexString),
    BlockCount = cryptopals_analysis:count_different_blocks(CipherString, 16),
    {BlockCount, HexString}
  end, Device),
  file:close(Device),
  {BlockCount, HexString} = cryptopals_lists:min(1, DifferentBlocks),

  #{input => io_lib:format("from file '~p'", [InputFile]),
    output => io_lib:format("~p different blocks found in ~p", [BlockCount, HexString])}.
