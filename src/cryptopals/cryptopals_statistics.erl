-module(cryptopals_statistics).
-author("Martin Schut <martin-github@wommm.nl").

%%
%% API
%%
-export([hamming/2, normalized_hamming/2, hellinger/2]).

hamming(BitString1, BitString2) ->
  Bits = cryptopals_bitsequence:bitstring_xor(BitString1, BitString2),
  HammingDistance = cryptopals_bitsequence:bitstring_foldl(fun(Bit, Acc) -> Acc + Bit end, Bits, 0),
  HammingDistance.

normalized_hamming(BitString1, BitString2) ->
  HammingDistance = hamming(BitString1, BitString2),
  MaxLength = max(byte_size(BitString1), byte_size(BitString1)),
  NormalizedHammingDistance = HammingDistance / MaxLength,
  NormalizedHammingDistance.

hellinger(ExpectedProbabilities, ObservedProbabilities) ->
  BhattacharyyaCoefficient = maps:fold(fun(Key, ExpectedProbability, Acc) ->
    Acc + math:sqrt(ExpectedProbability * maps:get(Key, ObservedProbabilities, 0))
  end, 0, ExpectedProbabilities),
  Hellinger = math:sqrt(1 - BhattacharyyaCoefficient),
  Hellinger.

