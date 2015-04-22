-module(cryptopals_crypto).
-author("Martin Schut <martin-github@wommm.nl").

%% API
-export([block_decrypt/3, pkcs7_padding/2]).

block_decrypt(aes_ecb128, Key, CipherText) ->
  BitSize = bit_size(Key),
  Ivec =  <<0:BitSize>>,
  << <<(crypto:block_decrypt(aes_cbc128, Key, Ivec, CipherBlock))/bitstring>> || <<CipherBlock:BitSize/bitstring>> <= CipherText>>.

pkcs7_padding(BitString, Bytes) ->
  ByteSize = byte_size(BitString),
  NumberOfPaddingBytes = Bytes - (ByteSize rem Bytes),
  PaddingList = cryptopals_utils:for(fun(_) -> <<NumberOfPaddingBytes>> end, 1, NumberOfPaddingBytes),
  PaddingBitString = list_to_bitstring(PaddingList),
  <<BitString/bitstring, PaddingBitString/bitstring>>.