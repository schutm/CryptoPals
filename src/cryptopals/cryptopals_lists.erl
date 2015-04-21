-module(cryptopals_lists).
-author("Martin Schut <martin-github@wommm.nl>").

%% API
-export([min/2]).

min(N, TupleList) when is_integer(N), is_list(TupleList) ->
  MinFun = fun(TupleA, TupleB) ->
    min_tuple(N, TupleA, TupleB)
  end,
  Result = lists:foldl(MinFun, hd(TupleList), tl(TupleList)),
  Result.


%%
%% Internal functions
%%
min_tuple(N, TupleA, TupleB) ->
  A = element(N, TupleA),
  B = element(N, TupleB),
  case A < B of
    true -> TupleA;
    false -> TupleB
  end.
