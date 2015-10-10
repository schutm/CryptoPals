-module(cryptopals_file).
-author("Martin Schut <martin-github@wommm.nl>").

%% API
-export([
  close/1,
  map/2,
  open/2,
  read/1]).

close(Device) ->
  file:close(Device).

map(Fun, Device) ->
  case io:get_line(Device, "") of
    eof  -> [];
    Line -> [Fun(lists:droplast(Line))|map(Fun, Device)]
  end.

open(FileName, Mode) ->
  Path = prefix_with_privdir(FileName),
  file:open(Path, Mode).


read(FileName) ->
  Path = prefix_with_privdir(FileName),
  file:read_file(Path).

%%
%% Internal functions
%%
prefix_with_privdir(FileName) ->
  PrivDir = code:priv_dir(cryptopals),
  filename:join(PrivDir, FileName).
