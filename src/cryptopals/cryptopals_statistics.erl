-module(cryptopals_statistics).
-author("Martin Schut <martin-github@wommm.nl").

%%
%% API
%%
-export([hellinger/2]).

hellinger(ExpectedProbabilities, ObservedProbabilities) ->
  BhattacharyyaCoefficient = maps:fold(fun(Key, ExpectedProbability, Acc) ->
    Acc + math:sqrt(ExpectedProbability * maps:get(Key, ObservedProbabilities, 0))
  end, 0, ExpectedProbabilities),
  math:sqrt(1 -  BhattacharyyaCoefficient).
