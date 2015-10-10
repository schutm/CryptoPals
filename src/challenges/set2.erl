-module(set2).
-author("Martin Schut <martin-github@wommm.nl>").

-export([
  all/0,
  implement_pkcs7_padding/0,
  implement_cbc_mode/0,
  an_ecb_cbc_detection_oracle/0,
  byte_at_a_time_ecb_decryption_simple/0,
  ecb_cut_and_paste/0,
  byte_at_a_time_ecb_decryption_harder/0]).

all() ->
  [
    {"Implement PKCS#7 padding", implement_pkcs7_padding},
    {"Implement CBC mode", implement_cbc_mode},
    {"An ECB/CBC detection oracle", an_ecb_cbc_detection_oracle},
    {"Byte-at-a-time ECB decryption (Simple)", byte_at_a_time_ecb_decryption_simple},
    {"ECB cut-and-paste", ecb_cut_and_paste},
    {"Byte-at-a-time ECB decryption (Harder)", byte_at_a_time_ecb_decryption_harder}
  ].

implement_pkcs7_padding() ->
  Input = <<"YELLOW SUBMARINE">>,

  Result = cryptopals_crypto:pad(pkcs7, Input, 20),

  #{input => io_lib:format("'~s'", [Input]),
    output => Result,
    expectation => solutions:solution({set2, implement_pkcs7_padding}),
    format => "~p"}.

implement_cbc_mode() ->
  InputFile = "10.txt",
  Key = <<"YELLOW SUBMARINE">>,
  IVec = <<0:(16 * 8)>>,

  {ok, Binary} = cryptopals_file:read(InputFile),
  CipherText = cryptopals_bitsequence:bitstring_from_base64(Binary),
  PlainText = cryptopals_crypto:decrypt(aes_cbc128, Key, IVec, CipherText),

  #{input => io_lib:format("from file ~p", [InputFile]),
    output => PlainText,
    expectation => solutions:solution({set2, implement_cbc_mode}),
    format => "~p"}.

an_ecb_cbc_detection_oracle() ->
  Input = cryptopals_bitsequence:copies(3, <<"YELLOW SUBMARINE">>),
  Guesses = 100,
  Oracle = ecb_cbc_oracle(),

  Detector = fun(_) ->
    { Mode, CipherText } = Oracle(Input),
    DetectedMode =  cryptopals_analysis:detect_block_cipher_mode(ciphertext, 16, CipherText),
    { Mode, DetectedMode }
  end,
  Detections = cryptopals_utils:for(Detector, 1, Guesses),
  Check = fun({Mode, Guess}) when Mode =:= Guess -> 1;
    (_) -> 0
  end,
  CorrectGuesses = lists:foldl(fun(Element, AccIn) -> AccIn + Check(Element) end, 0, Detections),

  #{input => io_lib:format("Making 100 guesses", []),
    output => [CorrectGuesses, Guesses],
    expectation => solutions:solution({set2, an_ecb_cbc_detection_oracle}),
    format => "~p out of ~p guesses were correct"}.

byte_at_a_time_ecb_decryption_simple() ->
  Input = <<"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK">>,
  Oracle = ecb_encryption_oracle_simple(Input),

  {BlockCipherMode, BlockCipherSize, _BlockCipherBlocks} = cryptopals_analysis:detect_block_cipher_info(Oracle),
  MessageLength = cryptopals_analysis:detect_message_length(Oracle),

  Result = cryptopals_analysis:decrypt_appended_secret(BlockCipherMode, Oracle, BlockCipherSize, 0, MessageLength),
  #{input => io_lib:format("'~s'", [Input]),
    output => Result,
    expectation => solutions:solution({set2, byte_at_a_time_ecb_decryption_simple}),
    format => "~p"}.

ecb_cut_and_paste() ->
  Email = <<"martin-github@wommm.nl">>,
  Oracle = profile_oracle(),

  OracleInfoCallback = fun(PlainText) -> Oracle(createProfile, PlainText) end,
  {aes_ecb128, BlockCipherSize, _BlockCipherBlocks} = cryptopals_analysis:detect_block_cipher_info(OracleInfoCallback),

  PaddedAdminBlock = cryptopals_crypto:pad(pkcs7, <<"admin">>, BlockCipherSize),
  ValidEmailToOverflowEmail = cryptopals_analysis:overflower(
    {<<"email=">>, Email, <<>>}, BlockCipherSize, fun cryptopals_utils:lengthen_email/2),
  CipherTextWithOverflowAdminBlock = Oracle(createProfile, <<ValidEmailToOverflowEmail/bytes, PaddedAdminBlock/bytes>>),
  AdminBlockPartition = byte_size(<< <<"email=">>/bytes, ValidEmailToOverflowEmail/bytes>>) div BlockCipherSize + 1,
  PartitionsWithOverflowAdminBlock = cryptopals_bitsequence:partition(CipherTextWithOverflowAdminBlock, BlockCipherSize),
  EncryptedRole = lists:nth(AdminBlockPartition, PartitionsWithOverflowAdminBlock),

  ValidEmailToOverflowRole = cryptopals_analysis:overflower(
    {<<"email=">>, Email, <<"&uid=10&role=">>}, BlockCipherSize, fun cryptopals_utils:lengthen_email/2),
  CipherTextWithOverflowRoleBlock = Oracle(createProfile, ValidEmailToOverflowRole),
  PartitionsWithOverflowRole = cryptopals_bitsequence:partition(CipherTextWithOverflowRoleBlock, BlockCipherSize),
  PartitionsWithoutRoleBlock = lists:droplast(PartitionsWithOverflowRole),
  CipherWithAdminRole = cryptopals_bitsequence:concat(PartitionsWithoutRoleBlock ++ [EncryptedRole]),

  Result = Oracle(getProfile, CipherWithAdminRole),

  #{input => io_lib:format("'~s'", [Email]),
    output => Result,
    expectation => solutions:solution({set2, ecb_cut_and_paste}),
    format => "~p"}.

byte_at_a_time_ecb_decryption_harder() ->
  Input = <<"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK">>,
  Oracle = ecb_encryption_oracle_harder(Input),

  {BlockCipherMode, BlockCipherSize, _BlockCipherBlocks} = cryptopals_analysis:detect_block_cipher_info(Oracle),
  PrefixLength = cryptopals_analysis:detect_prefix_length(Oracle, BlockCipherSize),
  MessageLength = cryptopals_analysis:detect_message_length(Oracle) - PrefixLength,

  Result = cryptopals_analysis:decrypt_appended_secret(BlockCipherMode, Oracle, BlockCipherSize, PrefixLength, MessageLength),

  #{input => io_lib:format("'~s'", [Input]),
    output => Result,
    expectation => solutions:solution({set2, byte_at_a_time_ecb_decryption_harder}),
    format => "~p"}.

%%
%% Internal methods: oracles
%%
ecb_cbc_oracle() ->
  fun(PlainText) ->
    BitString = cryptopals_bitsequence:random_infix(PlainText, [5, 10]),
    Key = cryptopals_crypto:random_key(16),
    IVec = cryptopals_crypto:random_ivec(16),
    Mode = cryptopals_utils:choose([aes_cbc128, aes_ecb128]),
    case Mode of
      aes_cbc128 -> {Mode, cryptopals_crypto:encrypt(aes_cbc128, Key, IVec, BitString)};
      aes_ecb128 -> {Mode, cryptopals_crypto:encrypt(aes_ecb128, Key, BitString)}
    end
  end.

ecb_encryption_oracle_simple(Input) ->
  Key = cryptopals_crypto:random_key(16),
  Secret = cryptopals_bitsequence:bitstring_from_base64(Input),
  fun(PlainText) ->
    BitString = <<PlainText/bitstring, Secret/bitstring>>,
    cryptopals_crypto:encrypt(aes_ecb128, Key, BitString)
  end.

ecb_encryption_oracle_harder(Input) ->
  Key = cryptopals_crypto:random_key(16),
  Prefix = cryptopals_bitsequence:random_bitstring([40, 40]),
  Secret = cryptopals_bitsequence:bitstring_from_base64(Input),
  fun(PlainText) ->
    BitString = <<Prefix/bitstring, PlainText/bitstring, Secret/bitstring>>,
    cryptopals_crypto:encrypt(aes_ecb128, Key, BitString)
  end.

profile_oracle() ->
  Key = cryptopals_crypto:random_key(16),
  fun
    (createProfile, Email) ->
      ProfileQueryString = profile_for(Email),
      cryptopals_crypto:encrypt(aes_ecb128, Key, ProfileQueryString);
    (getProfile, CipherText) ->
      ProfileQueryString = cryptopals_crypto:decrypt(aes_ecb128, Key, CipherText),
      cryptopals_utils:parse_querystring(ProfileQueryString)
  end.

profile_for(Email) ->
  nomatch = binary:match(Email, [<<"%">>, <<"&">>, <<"=">>]),
  << "email=", Email/bitstring, "&uid=10&role=user" >>.
