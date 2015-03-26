-module(cryptopals).
-author("Martin Schut <martin-github@wommm.nl>").

-define(AVAILABLE_SETS, [set1]).

%% API
-export([expect/2, solve/1]).

solve(ListOfChallengesToSolve) when is_list(ListOfChallengesToSolve) ->
  ChallengesToSolve = lists:filter(fun(Challenge) -> should_solve(Challenge, ListOfChallengesToSolve) end, all_challenges()),
  solve_challenges(ChallengesToSolve);
solve(all) ->
  solve_challenges(all_challenges());
solve(Challenge) ->
  solve([Challenge]).

expect(ExpectedOutput, Output) ->
  case Output of
    ExpectedOutput ->
      ok;
    _UnexpectedOutput ->
      io:fwrite("  Expected output: ~s~n", [ExpectedOutput]),
      failed
  end.

%%
%% Internal functions
%%
solve_challenges(ListOfChallengesToSolve) ->
  lists:foreach(fun(Challenge) -> solve_challenge(Challenge) end, ListOfChallengesToSolve).

solve_challenge({Set, Challenge}) ->
  SetNumber = list_to_integer(lists:filter(fun(C) -> C >= $0 andalso C =< $9 end, atom_to_list(Set))),
  io:fwrite("Set ~p, challenge ~p: ", [SetNumber, Challenge]),

  try Set:challenge(Challenge) of
    Map = #{input := Input, output := Output} ->
      io:fwrite("  Input: ~s~n", [Input]),
      io:fwrite("  Output: ~s~n", [Output]),
      case maps:get(expectation, Map, Output) of
        Output ->
          ok;
        ExpectedOutput ->
          io:fwrite("  Expected output: ~s~n", [ExpectedOutput ]),
          failed
      end
  catch
    Exception:Reason -> io:fwrite("  Caught '~p' due to ~p~n", [Exception, Reason])
  end.

should_solve(Challenge, ListOfChallengesToSolve) when is_list(ListOfChallengesToSolve) ->
  lists:any(fun(ChallengeToSolve) -> should_solve(Challenge, ChallengeToSolve) end, ListOfChallengesToSolve);
should_solve({SetToSolve, _ChallengeToSolve}, SetToSolve) -> true;
should_solve({_SetToSolve, ChallengeToSolve}, ChallengeToSolve) -> true;
should_solve({SetToSolve, ChallengeToSolve}, {SetToSolve, ChallengeToSolve}) -> true;
should_solve(_, _) -> false.

all_challenges() ->
  lists:flatten(lists:map(fun(Set) -> set_challenges(Set) end, ?AVAILABLE_SETS)).

set_challenges(Set) ->
  lists:map(fun(Challenge) -> create_challenge(Set, Challenge) end, Set:all()).

create_challenge(Set, Challenge) ->
  {Set, Challenge}.