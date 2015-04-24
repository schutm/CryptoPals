-module(cryptopals_crypto).
-author("Martin Schut <martin-github@wommm.nl").

%% API
-export([decrypt/3, decrypt/4, encrypt/3, encrypt/4, pad/3]).

decrypt(aes_ecb128, Key, CipherText) ->
  BitSize = bit_size(Key),
  Ivec =  <<0:BitSize>>,
  << <<(crypto:block_decrypt(aes_cbc128, Key, Ivec, CipherBlock))/bitstring>> || <<CipherBlock:BitSize/bitstring>> <= CipherText>>.

encrypt(aes_ecb128, Key, CipherText) ->
  BitSize = bit_size(Key),
  Ivec =  <<0:BitSize>>,
  << <<(crypto:block_encrypt(aes_cbc128, Key, Ivec, CipherBlock))/bitstring>> || <<CipherBlock:BitSize/bitstring>> <= CipherText>>.

decrypt(aes_cbc128, Key, IVec, CipherText) ->
  decrypt_acc(aes_cbc128, Key, IVec, CipherText, <<>>).

encrypt(aes_cbc128, Key, IVec, CipherText) ->
  encrypt_acc(aes_cbc128, Key, IVec, CipherText, <<>>).

pad(pkcs7, BitString, Bytes) ->
  ByteSize = byte_size(BitString),
  NumberOfPaddingBytes = Bytes - (ByteSize rem Bytes),
  PaddingList = cryptopals_utils:for(fun(_) -> <<NumberOfPaddingBytes>> end, 1, NumberOfPaddingBytes),
  PaddingBitString = list_to_bitstring(PaddingList),
  <<BitString/bitstring, PaddingBitString/bitstring>>.

%%
%% Internal functions
%%
decrypt_acc(aes_cbc128, _Key, _IVec, <<>>, Acc) ->
  Acc;
decrypt_acc(aes_cbc128, Key, IVec, CipherText, Acc) ->
  BitSize = bit_size(Key),
  <<Block:BitSize/bitstring, Rest/bitstring>> = CipherText,
  DecryptedBlock = decrypt(aes_ecb128, Key, Block),
  PlainBlock = cryptopals_bitsequence:bitstring_xor(DecryptedBlock, IVec),
  decrypt_acc(aes_cbc128, Key, Block, Rest, <<Acc/bitstring, PlainBlock/bitstring>>).

encrypt_acc(aes_cbc128, _Key, _IVec, <<>>, Acc) ->
  Acc;
encrypt_acc(aes_cbc128, Key, IVec, PlainText, Acc) ->
  BitSize = bit_size(Key),
  <<Block:BitSize/bitstring, Rest/bitstring>> = PlainText,
  XorredBlock = cryptopals_bitsequence:bitstring_xor(Block, IVec),
  EncryptedBlock = encrypt(aes_ecb128, Key, XorredBlock),
  encrypt_acc(aes_cbc128, Key, EncryptedBlock, Rest, <<Acc/bitstring, EncryptedBlock/bitstring>>).
