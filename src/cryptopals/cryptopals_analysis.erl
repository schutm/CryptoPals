-module(cryptopals_analysis).
-author("Martin Schut <martin-github@wommm.nl").

%%
%% API
%%
-export([
  count_different_blocks/2,
  decrypt_appended_secret/5,
  detect_block_cipher_info/1,
  detect_block_cipher_mode/3,
  detect_block_cipher_size/2,
  detect_message_length/1,
  detect_prefix_length/2,
  guess_key_size/2,
  guess_multiple_byte_xor/2,
  guess_single_byte_xor/2,
  overflower/3]).

count_different_blocks(BitString, Bytes) ->
  BlockCount = count_blocks_acc(BitString, Bytes, #{}),
  length(maps:keys(BlockCount)).

decrypt_appended_secret(BlockCipherMode, Oracle, BlockCipherSize, PrefixLength, MessageLength) ->
   decrypt_appended_block(BlockCipherMode, Oracle, BlockCipherSize, PrefixLength, MessageLength).

detect_block_cipher_info(EncryptionOracle) ->
  BlockSizeInBytes = detect_block_cipher_size(oracle, EncryptionOracle),
  Mode = detect_block_cipher_mode(oracle, BlockSizeInBytes, EncryptionOracle),
  Blocks = byte_size(EncryptionOracle(<<"">>)) div BlockSizeInBytes,
  {Mode, BlockSizeInBytes, Blocks}.

detect_block_cipher_mode(oracle, BlockSizeInBytes, EncryptionOracle) ->
  SingleBlockPlainText = cryptopals_bitsequence:copies(BlockSizeInBytes, <<"Y">>),
  PlainText = cryptopals_bitsequence:copies(3, SingleBlockPlainText),
  CipherText = EncryptionOracle(PlainText),
  detect_block_cipher_mode(ciphertext, BlockSizeInBytes, CipherText);
detect_block_cipher_mode(ciphertext, BlockSizeInBytes, CipherText) ->
  case has_two_consecutive_blocks(BlockSizeInBytes, CipherText) of
    true -> aes_ecb128;
    _ -> aes_cbc128
  end.

has_two_consecutive_blocks(BlockSizeInBytes, CipherText) ->
  <<Block1:BlockSizeInBytes/bytes, Block2:BlockSizeInBytes/bytes, Rest/bitstring>> = CipherText,
  if
    Block1 =:= Block2 -> true;
    Rest =:= <<>> -> false;
    true -> has_two_consecutive_blocks(BlockSizeInBytes, <<Block2/bitstring, Rest/bitstring>>)
  end.

detect_block_cipher_size(oracle, EncryptionOracle) ->
  {_Increment, InitialMessageSize, PaddedMessageSize} = detect_message_size_change(EncryptionOracle),
  PaddedMessageSize - InitialMessageSize.

detect_message_length(EncryptionOracle) ->
  {Increment, InitialMessageSize, _PaddedMessageSize} = detect_message_size_change(EncryptionOracle),
  InitialMessageSize - Increment.

detect_prefix_length(EncryptionOracle, BlockCipherSize) ->
  CipherText1 = EncryptionOracle(<<"">>),
  CipherText2 = EncryptionOracle(<<"$">>),
  BlockAlignedCommonPrefixSize = binary:longest_common_prefix([CipherText1, CipherText2]) div BlockCipherSize * BlockCipherSize,
  Incrementer = fun(Count) -> Count + 1 end,

  Fun = fun(Count) when Count =< BlockCipherSize ->
    PlainText = cryptopals_bitsequence:copies(2 * BlockCipherSize + Count, <<"$">>),
    EncryptionOracle(PlainText)
  end,
  Condition = fun(CipherText) ->
    CipherSubBitString = cryptopals_bitsequence:substr(CipherText, BlockAlignedCommonPrefixSize + 1, 3 * BlockCipherSize),
    Partitions = cryptopals_bitsequence:partition(CipherSubBitString, BlockCipherSize),
    case Partitions of
      [P, P, _] -> true;
      [_, P, P] -> true;
      _         -> false
    end
  end,

  {Increment, _CipherText} = cryptopals_utils:find_match(Fun, Condition, 1, Incrementer),
  BlockAlignedCommonPrefixSize + BlockCipherSize - Increment.

guess_key_size(CipherText, Guesses) ->
  Min = fun(
    {_, DistanceA} = _A, {_, DistanceB} = _B) when DistanceA =< DistanceB -> true;
    (_A, _B) -> false
  end,
  HammingDistances = [{Guess, average_hamming_distance(CipherText, Guess)} || Guess <- Guesses],
  SortedDistances = lists:sort(Min, HammingDistances),
  {Winner, _} = hd(SortedDistances),
  Winner.

guess_single_byte_xor(BitString, Language) ->
  Keys = lists:map(fun(E) -> <<E>> end, lists:seq(0, 255)),
  PlainTexts = [cryptopals_bitsequence:bitstring_xor(BitString, Key) || Key <- Keys],
  GoodnessOfFit = [goodness_of_fit(PlainText, Language) || PlainText <- PlainTexts],
  BestFit = lists:min(GoodnessOfFit),
  ResultTuples = lists:zip(Keys, GoodnessOfFit),
  Winner = lists:keyfind(BestFit, 2, ResultTuples),
  Winner.

guess_multiple_byte_xor(CipherText, GuessedSize) ->
  Blocks = cryptopals_bitsequence:unzip(CipherText, GuessedSize),
  GuessedBytePerBlock = [erlang:element(1, cryptopals_analysis:guess_single_byte_xor(Block, "EN")) || Block <- Blocks],
  Key = list_to_bitstring(GuessedBytePerBlock),
  Key.

overflower({Prefix, Infix, Postfix}, BlockSize, LengtheningFun) ->
  {PrefixSize, InfixSize, PostfixSize} = {byte_size(Prefix), byte_size(Infix), byte_size(Postfix)},
  RequiredBlocks = cryptopals_utils:ceiling((PrefixSize + InfixSize + PostfixSize) / BlockSize),
  RequiredBytesToOverflow = RequiredBlocks * BlockSize,
  RequiredBytesInfix = RequiredBytesToOverflow - PrefixSize - PostfixSize,
  LengtheningFun(Infix, RequiredBytesInfix).

%%
%% Internal functions
%%
average_hamming_distance(CipherText, Bytes) ->
  Partitions = cryptopals_bitsequence:partition(CipherText, Bytes),
  HammingDistances = hamming_distances(Partitions),
  AverageDistance = lists:sum(HammingDistances) / length(HammingDistances),
  AverageDistance.

count_blocks_acc(<<>>, _Bytes, Acc) ->
  Acc;
count_blocks_acc(BitString, Bytes, Acc) ->
  <<Block:Bytes/bytes, Rest/bitstring>> = BitString,
  NewBlockCount = maps:get(Block, Acc, 0) + 1,
  count_blocks_acc(Rest, Bytes, maps:put(Block, NewBlockCount, Acc)).

decrypt_appended_block(aes_ecb128, Oracle, BlockCipherSize, PrefixLength, UnknownLength) ->
   decrypt_appended_blocks_acc(aes_ecb128, Oracle, BlockCipherSize, PrefixLength, UnknownLength, 1, BlockCipherSize - 1, <<"">>).

decrypt_appended_blocks_acc(aes_ecb128, _Oracle, _BlockCipherSize, _PrefixLength, _UnknownLength = 0, _Block, _BytoToDecrypt, KnownMessage) ->
  KnownMessage;
decrypt_appended_blocks_acc(aes_ecb128, Oracle, BlockCipherSize, PrefixLength, UnknownLength, Block, BytoToDecrypt, KnownMessage) ->
  Byte = decrypt_byte(Oracle, BlockCipherSize, PrefixLength, Block, BytoToDecrypt, KnownMessage),

  case BytoToDecrypt of
    0 -> { NextBlock, NextByteToDecrypt } = { Block + 1, BlockCipherSize - 1 };
    _ -> { NextBlock, NextByteToDecrypt } = { Block, BytoToDecrypt - 1}
  end,
  decrypt_appended_blocks_acc(aes_ecb128, Oracle, BlockCipherSize, PrefixLength, UnknownLength - 1, NextBlock, NextByteToDecrypt, <<KnownMessage/bitstring, Byte>>).

decrypt_byte(Oracle, BlockCipherSize, PrefixLength, BlockToDecrypt, ByteToDecrypt, KnownMessage) ->
  Padding = padding(BlockCipherSize, PrefixLength, ByteToDecrypt),
  BlocksToSkip = (PrefixLength + byte_size(Padding)) div BlockCipherSize,
  CipherBlockToDecrypt = BlocksToSkip + BlockToDecrypt,
  CipherBlock = block(CipherBlockToDecrypt, Oracle(Padding), BlockCipherSize),
  Dictionary = [{block(CipherBlockToDecrypt, Oracle(<<Padding/bitstring, KnownMessage/bitstring, Byte>>), BlockCipherSize), Byte} || Byte <- lists:seq(0, 255)],
  {_EncryptedBlock, Byte} = lists:keyfind(CipherBlock, 1, Dictionary),
  Byte.

block(CipherBlockToDecrypt, CipherText, BlockCipherSize) ->
  lists:nth(CipherBlockToDecrypt, cryptopals_bitsequence:partition(CipherText, BlockCipherSize)).

padding(BlockCipherSize, PrefixLength, MessaageBlockByte) ->
  PrefixPartialBlockLength = PrefixLength rem BlockCipherSize,
  PrefixPaddingLength = (BlockCipherSize - PrefixPartialBlockLength) rem BlockCipherSize,
  PrefixPadding = cryptopals_bitsequence:copies(PrefixPaddingLength, <<"A">>),
  OverflowPadding = cryptopals_bitsequence:copies(MessaageBlockByte, <<"B">>),
  <<PrefixPadding/bitstring, OverflowPadding/bitstring>>.

encrypted_size_with_padding(EncryptionOracle, PaddingBytes) ->
  KnownString = cryptopals_bitsequence:copies(PaddingBytes, <<"A">>),
  byte_size(EncryptionOracle(KnownString)).

detect_message_size_change(EncryptionOracle) ->
  InitialMessageSize = encrypted_size_with_padding(EncryptionOracle, 0),
  Condition = fun(Result) ->
    case Result of
      InitialMessageSize -> false;
      _Else -> true
    end
  end,
  Incrementer = fun(Count) -> Count + 1 end,
  {Increment, MessageSize} = cryptopals_utils:find_match(
    fun(Count) -> encrypted_size_with_padding(EncryptionOracle, Count) end, Condition, 1, Incrementer),
  {Increment, InitialMessageSize, MessageSize}.

hamming_distances(Partitions) ->
  HammingDistances = hamming_distances_acc(Partitions, []),
  HammingDistances.

hamming_distances_acc([Block1, Block2|Rest], Acc) ->
  NormalizedHammingDistance = cryptopals_statistics:normalized_hamming(Block1, Block2),
  hamming_distances_acc([Block2] ++ Rest, [NormalizedHammingDistance|Acc]);
hamming_distances_acc([_LastBlock], Acc) ->
  Acc.

goodness_of_fit(Text, Language) ->
  ExpectedProbabilities = letter_frequency( Language),

  UpperCaseText = cryptopals_bitsequence:uppercase(Text),
  TextFrequency = frequency_count(UpperCaseText),
  ObservedProbabilities = normalize(TextFrequency),

  cryptopals_statistics:hellinger(ExpectedProbabilities, ObservedProbabilities).

frequency_count(Characters) -> frequency_count(Characters, #{}).
frequency_count(<<>>, M) -> M;
frequency_count(<<Character:8/bitstring, Rest/bitstring>>, M) ->
  Frequency = maps:get(Character, M, 0) + 1,
  M2 = maps:put(Character, Frequency, M),
  frequency_count(Rest, M2).

normalize(Values) ->
  Total = lists:sum(maps:values(Values)),
  maps:map(fun(_K, V) -> V / Total end, Values).

%% Taken from: http://data-compression.com/english.html
letter_frequency("EN") ->
  #{
    <<"A">> => 0.0651738, <<"B">> => 0.0124248, <<"C">> => 0.0217339, <<"D">> => 0.0349835,
    <<"E">> => 0.1041442, <<"F">> => 0.0197881, <<"G">> => 0.0158610, <<"H">> => 0.0492888,
    <<"I">> => 0.0558094, <<"J">> => 0.0009033, <<"K">> => 0.0050529, <<"L">> => 0.0331490,
    <<"M">> => 0.0202124, <<"N">> => 0.0564513, <<"O">> => 0.0596302, <<"P">> => 0.0137645,
    <<"Q">> => 0.0008606, <<"R">> => 0.0497563, <<"S">> => 0.0515760, <<"T">> => 0.0729357,
    <<"U">> => 0.0225134, <<"V">> => 0.0082903, <<"W">> => 0.0171272, <<"X">> => 0.0013692,
    <<"Y">> => 0.0145984, <<"Z">> => 0.0007836, <<" ">> => 0.1918182
  }.
