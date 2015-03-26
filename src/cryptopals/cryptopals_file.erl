-module(cryptopals_file).
-author("Martin Schut <martin-github@wommm.nl>").

%% API
-export([map/2]).

map(Fun, Device) ->
  case io:get_line(Device, "") of
    eof  -> [];
    Line -> [Fun(lists:droplast(Line))|map(Fun, Device)]
  end.
