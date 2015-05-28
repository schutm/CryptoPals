-module(cryptopals_crypto).
-author("Martin Schut <martin-github@wommm.nl").

%% API
-export([
  decrypt/3,
  decrypt/4,
  encrypt/3,
  encrypt/4,
  encryption_oracle/1,
  pad/3,
  unpad/2]).

decrypt(aes_ecb128, Key, CipherText) ->
  PaddedPlainText = block_decrypt(aes_ecb128, Key, CipherText),
  unpad(pkcs7, PaddedPlainText).

encrypt(aes_ecb128, Key, PlainText) ->
  PaddedPlainText = pad(pkcs7, PlainText, byte_size(Key)),
  block_encrypt(aes_ecb128, Key, PaddedPlainText).

decrypt(aes_cbc128, Key, IVec, CipherText) ->
  PaddedPlainText = block_decrypt(aes_cbc128, Key, IVec, CipherText),
  unpad(pkcs7, PaddedPlainText).

encrypt(aes_cbc128, Key, IVec, PlainText) ->
  PaddedPlainText = pad(pkcs7, PlainText, byte_size(Key)),
  block_encrypt(aes_cbc128, Key, IVec, PaddedPlainText).

encryption_oracle(PlainText) ->
  BitString = embed_bitstring(PlainText),
  Key = crypto:strong_rand_bytes(16),
  IVec = crypto:strong_rand_bytes(16),
  Mode = cryptopals_utils:choose([aes_cbc128, aes_ecb128]),
  case Mode of
    aes_cbc128 -> { Mode, encrypt(aes_cbc128, Key, IVec, BitString) };
    aes_ecb128 -> { Mode, encrypt(aes_ecb128, Key, BitString) }
  end.

pad(pkcs7, BitString, Bytes) ->
  ByteSize = byte_size(BitString),
  NumberOfPaddingBytes = Bytes - (ByteSize rem Bytes),
  Padding = padding(NumberOfPaddingBytes),
  <<BitString/bitstring, Padding/bitstring>>.

unpad(pkcs7, PaddedBitString) ->
  Bytes = byte_size(PaddedBitString),
  <<NumberOfPaddingBytes>> = binary:part(PaddedBitString, {byte_size(PaddedBitString), -1}),
  NumberOfTextBytes = Bytes - NumberOfPaddingBytes,
  <<BitString:NumberOfTextBytes/bytes, Padding:NumberOfPaddingBytes/bytes>> = PaddedBitString,
  Padding = padding(NumberOfPaddingBytes),
  BitString.

%%
%% Internal functions
%%
block_decrypt(aes_ecb128, Key, CipherText) ->
  BitSize = bit_size(Key),
  IVec = <<0:BitSize>>,
  << <<(crypto:block_decrypt(aes_cbc128, Key, IVec, CipherBlock))/bitstring>> || <<CipherBlock:BitSize/bitstring>> <= CipherText>>.

block_encrypt(aes_ecb128, Key, PaddedPlainText) ->
  BitSize = bit_size(Key),
  IVec = <<0:BitSize>>,
  << <<(crypto:block_encrypt(aes_cbc128, Key, IVec, PlainBlock))/bitstring>> || <<PlainBlock:BitSize/bitstring>> <= PaddedPlainText>>.

block_decrypt(aes_cbc128, Key, IVec, CipherText) ->
  block_decrypt_acc(aes_cbc128, Key, IVec, CipherText, <<>>).

block_encrypt(aes_cbc128, Key, IVec, PaddedPlainText) ->
  block_encrypt_acc(aes_cbc128, Key, IVec, PaddedPlainText, <<>>).

block_decrypt_acc(aes_cbc128, _Key, _IVec, <<>>, Acc) ->
  Acc;
block_decrypt_acc(aes_cbc128, Key, IVec, CipherText, Acc) ->
  BitSize = bit_size(Key),
  <<Block:BitSize/bitstring, Rest/bitstring>> = CipherText,
  DecryptedBlock = block_decrypt(aes_ecb128, Key, Block),
  PlainBlock = cryptopals_bitsequence:bitstring_xor(DecryptedBlock, IVec),
  block_decrypt_acc(aes_cbc128, Key, Block, Rest, <<Acc/bitstring, PlainBlock/bitstring>>).

block_encrypt_acc(aes_cbc128, _Key, _IVec, <<>>, Acc) ->
  Acc;
block_encrypt_acc(aes_cbc128, Key, IVec, PlainText, Acc) ->
  BitSize = bit_size(Key),
  <<Block:BitSize/bitstring, Rest/bitstring>> = PlainText,
  XorredBlock = cryptopals_bitsequence:bitstring_xor(Block, IVec),
  EncryptedBlock = block_encrypt(aes_ecb128, Key, XorredBlock),
  block_encrypt_acc(aes_cbc128, Key, EncryptedBlock, Rest, <<Acc/bitstring, EncryptedBlock/bitstring>>).

embed_bitstring(Bitstring) ->
  PreBytes = crypto:strong_rand_bytes(random:uniform(6) + 4),
  PostBytes = crypto:strong_rand_bytes(random:uniform(6) + 4),
  <<PreBytes/bitstring, Bitstring/bitstring, PostBytes/bitstring>>.

padding(NumberOfPaddingBytes) ->
  PaddingList = cryptopals_utils:for(fun(_) -> <<NumberOfPaddingBytes>> end, 1, NumberOfPaddingBytes),
  list_to_bitstring(PaddingList).
