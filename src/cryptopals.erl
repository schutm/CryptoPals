-module(cryptopals).
-author("Martin Schut <martin-github@wommm.nl>").

-define(AVAILABLE_SETS, [set1, set2]).

%% API
-export([solve/1]).

%% Any combination of Set and { Set, Challenge } is allowed. In addition if only 1
%% set or challenge should be solved no list is required. As special case the atom
%% all indicates all challenges.
solve(all) ->
  solve(all_challenges());
solve(Set) when is_atom(Set) ->
  solve(set_challenges(Set));
solve([Challenge|RemainingChallenges]) ->
  solve(Challenge),
  solve(RemainingChallenges);
solve([]) ->
  ok;
solve({_Set, _Challenge} = Challenge) ->
  solve_challenge(Challenge).

%%
%% Internal functions
%%
solve_challenge({Set, Challenge}) when not is_tuple(Challenge) ->
  [FirstLetter|Title] = string:join(string:tokens(atom_to_list(Challenge), "_"), " "),
  solve_challenge({Set, {[string:to_upper(FirstLetter)|Title], Challenge}});
solve_challenge({Set, {Title, Challenge}}) ->
  write_title(Set, Title),

  try Set:Challenge() of
    Result ->
      write_result(Result),
      maybe_write_information(Result)
  catch
    Exception:Reason -> io:fwrite("  Caught '~p' due to ~p~n", [Exception, Reason])
  end.

write_title(Set, Title) ->
  SetNumber = lists:filter(fun(C) -> C >= $0 andalso C =< $9 end, atom_to_list(Set)),
  io:fwrite("Set ~s - challenge '~s': ", [SetNumber, Title]).

write_result(#{output := Output, expectation := ExpectedOutput}) when Output =:= ExpectedOutput ->
  io:fwrite("solved~n");
write_result(_) ->
  io:fwrite("failed~n").

maybe_write_information(#{input := Input, output := Output, expectation := ExpectedOutput, format := Format}) when Output =/= ExpectedOutput ->
  io:fwrite("  Input: ~s~n", [Input]),
  io:fwrite("  Output: ~s~n", [io_lib:format(Format, [Output])]),
  io:fwrite("  Expected output: ~s~n", [io_lib:format(Format, [ExpectedOutput])]),
  ok;
maybe_write_information(_) ->
  ok.

all_challenges() ->
  lists:flatten([set_challenges(Set) || Set <- ?AVAILABLE_SETS]).

set_challenges(Set) ->
  [{Set, Challenge} || Challenge <- Set:all()].
