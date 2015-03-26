-module(cryptopals_analysis).
-author("Martin Schut <martin-github@wommm.nl").

%%
%% API
%%
-export([goodness_of_fit/2]).

goodness_of_fit(Text, Language) ->
  ExpectedProbabilities = letter_frequency( Language),

  UpperCaseText = cryptopals_bitsequence:bitstring_uppercase(Text),
  TextFrequency = frequency_count(UpperCaseText),
  ObservedProbabilities = normalize(TextFrequency),

  cryptopals_statistics:hellinger(ExpectedProbabilities, ObservedProbabilities).

%%
%% Internal functions
%%
frequency_count(Characters) -> frequency_count(Characters, #{}).
frequency_count(<<>>, M) -> M;
frequency_count(<<Character:8/bitstring, Rest/bitstring>>, M) ->
  Frequency = maps:get(Character, M, 0) + 1,
  M2 = maps:put(Character, Frequency, M),
  frequency_count(Rest, M2).

normalize(Values) ->
  Total = lists:sum(maps:values(Values)),
  maps:map(fun(_K, V) -> V / Total end, Values).

%%% Takern from: http://data-compression.com/english.html
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
