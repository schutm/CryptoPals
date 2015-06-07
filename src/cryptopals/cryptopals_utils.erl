-module(cryptopals_utils).
-author("Martin Schut <martin-github@wommm.nl>").

%% API
-export([
  ceiling/1,
  choose/1,
  find_match/4,
  for/3]).

ceiling(X) when X < 0 ->
  trunc(X);
ceiling(X) ->
  T = trunc(X),
  case X - T == 0 of
    true -> T;
    false -> T + 1
  end.

choose(List) ->
  Item = random:uniform(length(List)),
  lists:nth(Item, List).

find_match(Fun, Condition, InitialValue, Incrementer) ->
  Value = Fun(InitialValue),
  case Condition(Value) of
    true -> { InitialValue, Value };
    _    -> find_match(Fun, Condition, Incrementer(InitialValue), Incrementer)
  end.

for(Fun, Min, Max) when is_integer(Min), is_integer(Max), Min =< Max ->
  for_acc(Fun, Min, Max, []).

%%
%% Internal functions
%%
for_acc(Fun, Max, Max, Acc) ->
  lists:reverse([Fun(Max)|Acc]);
for_acc(Fun, I, Max, Acc) ->
  for_acc(Fun, I+1, Max, [Fun(I)|Acc]).
