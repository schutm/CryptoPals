-module(set2).
-author("Martin Schut <martin-github@wommm.nl>").

-export([
  all/0,
  implement_pkcs7_padding/0,
  implement_cbc_mode/0]).

all() ->
  [
    {"Implement PKCS#7 padding", implement_pkcs7_padding},
    {"Implement CBC mode", implement_cbc_mode}
  ].

implement_pkcs7_padding() ->
  Input = <<"YELLOW SUBMARINE">>,
  Expected = <<$', "YELLOW SUBMARINE", 4, 4, 4, 4, $'>>,

  Result = cryptopals_crypto:pad(pkcs7, Input, 20),

  #{input => Input,
    output => io_lib:format("'~s'", [Result]),
    expectation => Expected}.

implement_cbc_mode() ->
  InputFile = "./data/10.txt",
  Key = <<"YELLOW SUBMARINE">>,
  IVec = <<0:(16 * 8)>>,

  {ok, Binary} = file:read_file(InputFile),
  CipherText = cryptopals_bitsequence:bitstring_from_base64(Binary),
  PlainText = cryptopals_crypto:decrypt(aes_cbc128, Key, IVec, CipherText),

  #{input => io_lib:format("from file ~p", [InputFile]),
    output => PlainText}.
