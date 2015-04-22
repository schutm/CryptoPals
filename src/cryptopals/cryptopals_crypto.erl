-module(cryptopals_crypto).
-author("Martin Schut <martin-github@wommm.nl").

%% API
-export([block_decrypt/3]).

block_decrypt(aes_ecb128, Key, CipherText) ->
  BitSize = bit_size(Key),
  Ivec =  <<0:BitSize>>,
  << <<(crypto:block_decrypt(aes_cbc128, Key, Ivec, CipherBlock))/bitstring>> || <<CipherBlock:BitSize/bitstring>> <= CipherText>>.

