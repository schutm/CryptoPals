-module(cryptopals_utils).
-author("Martin Schut <martin-github@wommm.nl>").

%% API
-export([
  ceiling/1,
  choose/1,
  find_match/4,
  for/3,
  lengthen_email/2,
  read_data/1,
  open_file/2,
  close_file/1,
  parse_querystring/1]).

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

lengthen_email(Email, RequiredLength) ->
  OneShort = RequiredLength - 1,
  case byte_size(Email) of
    RequiredLength -> Email;
    OneShort       -> << Email/bytes, <<".">>/bytes >>;
    EmailLength    ->
      CommentLength = RequiredLength - EmailLength - 2,
      Comment = cryptopals_bitsequence:copies(CommentLength, <<"A">>),
      << <<"(">>/bytes, Comment/bytes,  <<")">>/bytes, Email/bytes>>
  end.

open_file(FileName, Mode) ->
  Path = prefix_with_privdir(FileName),
  file:open(Path, Mode).

close_file(Device) ->
  file:close(Device).

read_data(FileName) ->
  Path = prefix_with_privdir(FileName),
  file:read_file(Path).

parse_querystring(BitString) ->
  KeyValuePairs = binary:split(BitString, [<<"&">>], [global, trim]),
  lists:map(fun(KeyValue) -> erlang:list_to_tuple(binary:split(KeyValue, [<<"=">>])) end, KeyValuePairs).

%%
%% Internal functions
%%
for_acc(Fun, Max, Max, Acc) ->
  lists:reverse([Fun(Max)|Acc]);
for_acc(Fun, I, Max, Acc) ->
  for_acc(Fun, I+1, Max, [Fun(I)|Acc]).

prefix_with_privdir(FileName) ->
  PrivDir = code:priv_dir(cryptopals),
  filename:join(PrivDir, FileName).
