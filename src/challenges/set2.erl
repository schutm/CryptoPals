-module(set2).
-author("Martin Schut <martin-github@wommm.nl>").

-export([
  all/0,
  implement_pkcs7_padding/0,
  implement_cbc_mode/0,
  an_ecb_cbc_detection_oracle/0,
  byte_at_a_time_ecb_decryption_simple/0]).

all() ->
  [
    {"Implement PKCS#7 padding", implement_pkcs7_padding},
    {"Implement CBC mode", implement_cbc_mode},
    {"An ECB/CBC detection oracle", an_ecb_cbc_detection_oracle},
    {"Byte-at-a-time ECB decryption (Simple)", byte_at_a_time_ecb_decryption_simple}
  ].

implement_pkcs7_padding() ->
  Input = <<"YELLOW SUBMARINE">>,

  Result = cryptopals_crypto:pad(pkcs7, Input, 20),

  #{input => io_lib:format("'~s'", [Input]),
    output => Result,
    expectation => solutions:solution({set2, implement_pkcs7_padding}),
    format => "~p"}.

implement_cbc_mode() ->
  InputFile = "./data/10.txt",
  Key = <<"YELLOW SUBMARINE">>,
  IVec = <<0:(16 * 8)>>,

  {ok, Binary} = file:read_file(InputFile),
  CipherText = cryptopals_bitsequence:bitstring_from_base64(Binary),
  PlainText = cryptopals_crypto:decrypt(aes_cbc128, Key, IVec, CipherText),

  #{input => io_lib:format("from file ~p", [InputFile]),
    output => PlainText,
    expectation => solutions:solution({set2, implement_cbc_mode}),
    format => "~p"}.

an_ecb_cbc_detection_oracle() ->
  Input = cryptopals_bitsequence:bitstring_copies(3, <<"YELLOW SUBMARINE">>),
  Guesses = 100,
  Oracle = ecb_cbc_oracle(),

  Detector = fun(_) ->
    { Mode, CipherText } = Oracle(Input),
    DetectedMode =  cryptopals_analysis:detect_block_cipher_mode(ciphertext, CipherText),
    { Mode, DetectedMode }
  end,
  Detections = cryptopals_utils:for(Detector, 1, Guesses),
  Check = fun({Mode, Guess}) when Mode =:= Guess -> 1;
    (_) -> 0
  end,
  CorrectGuesses = lists:foldl(fun(Element, AccIn) -> AccIn + Check(Element) end, 0, Detections),

  #{input => io_lib:format("Making 100 guesses", []),
    output => [CorrectGuesses, Guesses],
    expectation => solutions:solution({set2, an_ecb_cbc_detection_oracle}),
    format => "~p out of ~p guesses were correct"}.

byte_at_a_time_ecb_decryption_simple() ->
  Input = <<"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK">>,
  Oracle = ecb_encryption_oracle(Input),

  {BlockCipherMode, BlockCipherSize, _BlockCipherBlocks} = cryptopals_analysis:detect_block_cipher_info(Oracle),
  MessageLength = cryptopals_analysis:detect_message_length(Oracle),

  Result = cryptopals_analysis:decrypt_appended_secret(Oracle, BlockCipherMode, BlockCipherSize, MessageLength),
  #{input => io_lib:format("'~s'", [Input]),
    output => Result,
    expectation => solutions:solution({set2, byte_at_a_time_ecb_decryption_simple}),
    format => "~p"}.

%%
%% Internal methods: oracles
%%
ecb_cbc_oracle() ->
  fun(PlainText) ->
    BitString = cryptopals_bitsequence:bitstring_within_random(PlainText, [5, 10]),
    Key = cryptopals_crypto:random_key(16),
    IVec = cryptopals_crypto:random_ivec(16),
    Mode = cryptopals_utils:choose([aes_cbc128, aes_ecb128]),
    case Mode of
      aes_cbc128 -> {Mode, cryptopals_crypto:encrypt(aes_cbc128, Key, IVec, BitString)};
      aes_ecb128 -> {Mode, cryptopals_crypto:encrypt(aes_ecb128, Key, BitString)}
    end
  end.

ecb_encryption_oracle(Input) ->
  Key = cryptopals_crypto:random_key(16),
  Secret = cryptopals_bitsequence:bitstring_from_base64(Input),
  fun(PlainText) ->
    BitString = <<PlainText/bitstring, Secret/bitstring>>,
    cryptopals_crypto:encrypt(aes_ecb128, Key, BitString)
  end.
