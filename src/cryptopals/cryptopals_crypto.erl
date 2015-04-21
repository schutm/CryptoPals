-module(cryptopals_crypto).
-author("Martin Schut <martin-github@wommm.nl").

%% API
-export([block_decrypt/4]).

block_decrypt(aes_ecb128, Key, Ivec, CipherText) ->
  BitSize = bit_size(Key),
  << <<(crypto:block_decrypt(aes_cbc128, Key, Ivec, CipherBlock))/bitstring>> || <<CipherBlock:BitSize/bitstring>> <= CipherText>>.

