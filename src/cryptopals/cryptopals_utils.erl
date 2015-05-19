-module(cryptopals_utils).
-author("Martin Schut <martin-github@wommm.nl>").

%% API
-export([
  for/3,
  choose/1]).

for(Fun, Min, Max) when is_integer(Min), is_integer(Max), Min =< Max ->
  for_acc(Fun, Min, Max, []).

choose(List) ->
  Item = random:uniform(length(List)),
  lists:nth(Item, List).

%%
%% Internal functions
%%
for_acc(Fun, Max, Max, Acc) ->
  lists:reverse([Fun(Max)|Acc]);
for_acc(Fun, I, Max, Acc) ->
  for_acc(Fun, I+1, Max, [Fun(I)|Acc]).
