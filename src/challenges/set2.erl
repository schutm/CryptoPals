-module(set2).
-author("Martin Schut <martin-github@wommm.nl>").

-export([
  all/0,
  implement_pkcs7_padding/0]).

all() ->
  [
    {"Implement PKCS#7 padding", implement_pkcs7_padding}
  ].

implement_pkcs7_padding() ->
  Input = <<"YELLOW SUBMARINE">>,
  Expected = <<"YELLOW SUBMARINE", 4, 4, 4, 4>>,

  Result = cryptopals_crypto:pkcs7_padding(Input, 20),

  #{input => Input,
    output => Result,
    expectation => Expected}.
