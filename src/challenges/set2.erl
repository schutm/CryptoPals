-module(set2).
-author("Martin Schut <martin-github@wommm.nl>").

-export([
  all/0,
  implement_pkcs7_padding/0,
  implement_cbc_mode/0,
  an_ecb_cbc_detection_oracle/0]).

all() ->
  [
    {"Implement PKCS#7 padding", implement_pkcs7_padding},
    {"Implement CBC mode", implement_cbc_mode},
    {"An ECB/CBC detection oracle", an_ecb_cbc_detection_oracle}
  ].

implement_pkcs7_padding() ->
  Input = <<"YELLOW SUBMARINE">>,

  Result = cryptopals_crypto:pad(pkcs7, Input, 20),

  #{input => io_lib:format("'~s'", [Input]),
    output => Result,
    expectation => solutions:solution({set2, implement_pkcs7_padding})}.

implement_cbc_mode() ->
  InputFile = "./data/10.txt",
  Key = <<"YELLOW SUBMARINE">>,
  IVec = <<0:(16 * 8)>>,

  {ok, Binary} = file:read_file(InputFile),
  CipherText = cryptopals_bitsequence:bitstring_from_base64(Binary),
  PlainText = cryptopals_crypto:decrypt(aes_cbc128, Key, IVec, CipherText),

  #{input => io_lib:format("from file ~p", [InputFile]),
    output => PlainText,
    expectation => solutions:solution({set2, implement_cbc_mode})}.

an_ecb_cbc_detection_oracle() ->
  Input = <<"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE">>,
  Guesses = 100,

  Detector = fun(_) ->
    { Mode, CipherText } = cryptopals_crypto:encryption_oracle(Input),
    DetectedMode =  cryptopals_analysis:detect_block_cipher_mode(CipherText),
    { Mode, DetectedMode }
  end,
  Detections = cryptopals_utils:for(Detector, 1, Guesses),
  Check = fun({Mode, Guess}) when Mode =:= Guess -> 1;
    (_) -> 0
  end,
  CorrectGuesses = lists:foldl(fun(Element, AccIn) -> AccIn + Check(Element) end, 0, Detections),

  #{input => io_lib:format("Making 100 guesses", []),
    output => lists:flatten(io_lib:format("~p out of ~p guesses were correct", [CorrectGuesses, Guesses])),
    expectation => solutions:solution({set2, an_ecb_cbc_detection_oracle})}.

