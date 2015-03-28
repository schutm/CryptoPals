-module(cryptopals).
-author("Martin Schut <martin-github@wommm.nl>").

-define(AVAILABLE_SETS, [set1]).

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
      write_input(Result),
      write_output(Result),
      maybe_write_expectation(Result)
  catch
    Exception:Reason -> io:fwrite("  Caught '~p' due to ~p~n", [Exception, Reason])
  end.

write_title(Set, Title) ->
  SetNumber = lists:filter(fun(C) -> C >= $0 andalso C =< $9 end, atom_to_list(Set)),
  io:fwrite("Set ~s - challenge '~s'~n", [SetNumber, Title]).

write_input(#{input := Input}) ->
  io:fwrite("  Input: ~s~n", [Input]).

write_output(#{output := Output}) ->
  io:fwrite("  Output: ~s~n", [Output]).

maybe_write_expectation(#{output := Output, expectation := ExpectedOutput}) when Output =:= ExpectedOutput ->
  ok;
maybe_write_expectation(#{expectation := ExpectedOutput}) ->
  io:fwrite("  Expected output: ~s~n", [ExpectedOutput]);
maybe_write_expectation(#{}) ->
  ok.

all_challenges() ->
  lists:flatten([set_challenges(Set) || Set <- ?AVAILABLE_SETS]).

set_challenges(Set) ->
  [{Set, Challenge} || Challenge <- Set:all()].
