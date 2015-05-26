-module(solutions).
-author("Martin Schut <martin-github@wommm.nl>").

-export([
  solution/1]).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%% SPOILER ALERT: SOLUTIONS TO SET 1 %%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
solution({set1, convert_hex_to_base64}) ->
  <<"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t">>;
solution({set1, fixed_xor})->
  <<"746865206b696420646f6e277420706c6179">>;
solution({set1, single_byte_xor}) ->
  [<<"X">>, <<"Cooking MC's like a pound of bacon">>];
solution({set1, detect_single_character_xor})  ->
  [<<"5">>, <<"Now that the party is jumping\n">>, <<"7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f">>];
solution({set1, implement_repeating_key_xor}) ->
  <<"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f">>;
solution({set1, break_repeating_key_xor}) ->
  [<<"Terminator X: Bring the noise">>, lyrics(vanilla_ice, play_that_funky_music)];
solution({set1, aes_in_ecb_mode}) ->
  << (lyrics(vanilla_ice, play_that_funky_music))/bitstring, <<4, 4, 4, 4>>/bitstring >>;
solution({set1, detect_aes_in_ecb_mode}) ->
  [7, <<"d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a">>];


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%% SPOILER ALERT: SOLUTIONS TO SET 2 %%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
solution({set2, implement_pkcs7_padding}) ->
  <<"YELLOW SUBMARINE", 4, 4, 4, 4>>;
solution({set2, implement_cbc_mode}) ->
  << (lyrics(vanilla_ice, play_that_funky_music))/bitstring, <<4, 4, 4, 4>>/bitstring >>;
solution({set2, an_ecb_cbc_detection_oracle}) ->
  [100, 100].

lyrics(vanilla_ice, play_that_funky_music) ->
  <<"I'm back and I'm ringin' the bell \n"
  "A rockin' on the mike while the fly girls yell \n"
  "In ecstasy in the back of me \n"
  "Well that's my DJ Deshay cuttin' all them Z's \n"
  "Hittin' hard and the girlies goin' crazy \n"
  "Vanilla's on the mike, man I'm not lazy. \n"
  "\n"
  "I'm lettin' my drug kick in \n"
  "It controls my mouth and I begin \n"
  "To just let it flow, let my concepts go \n"
  "My posse's to the side yellin', Go Vanilla Go! \n"
  "\n"
  "Smooth 'cause that's the way I will be \n"
  "And if you don't give a damn, then \n"
  "Why you starin' at me \n"
  "So get off 'cause I control the stage \n"
  "There's no dissin' allowed \n"
  "I'm in my own phase \n"
  "The girlies sa y they love me and that is ok \n"
  "And I can dance better than any kid n' play \n"
  "\n"
  "Stage 2 -- Yea the one ya' wanna listen to \n"
  "It's off my head so let the beat play through \n"
  "So I can funk it up and make it sound good \n"
  "1-2-3 Yo -- Knock on some wood \n"
  "For good luck, I like my rhymes atrocious \n"
  "Supercalafragilisticexpialidocious \n"
  "I'm an effect and that you can bet \n"
  "I can take a fly girl and make her wet. \n"
  "\n"
  "I'm like Samson -- Samson to Delilah \n"
  "There's no denyin', You can try to hang \n"
  "But you'll keep tryin' to get my style \n"
  "Over and over, practice makes perfect \n"
  "But not if you're a loafer. \n"
  "\n"
  "You'll get nowhere, no place, no time, no girls \n"
  "Soon -- Oh my God, homebody, you probably eat \n"
  "Spaghetti with a spoon! Come on and say it! \n"
  "\n"
  "VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \n"
  "Intoxicating so you stagger like a wino \n"
  "So punks stop trying and girl stop cryin' \n"
  "Vanilla Ice is sellin' and you people are buyin' \n"
  "'Cause why the freaks are jockin' like Crazy Glue \n"
  "Movin' and groovin' trying to sing along \n"
  "All through the ghetto groovin' this here song \n"
  "Now you're amazed by the VIP posse. \n"
  "\n"
  "Steppin' so hard like a German Nazi \n"
  "Startled by the bases hittin' ground \n"
  "There's no trippin' on mine, I'm just gettin' down \n"
  "Sparkamatic, I'm hangin' tight like a fanatic \n"
  "You trapped me once and I thought that \n"
  "You might have it \n"
  "So step down and lend me your ear \n"
  "'89 in my time! You, '90 is my year. \n"
  "\n"
  "You're weakenin' fast, YO! and I can tell it \n"
  "Your body's gettin' hot, so, so I can smell it \n"
  "So don't be mad and don't be sad \n"
  "'Cause the lyrics belong to ICE, You can call me Dad \n"
  "You're pitchin' a fit, so step back and endure \n"
  "Let the witch doctor, Ice, do the dance to cure \n"
  "So come up close and don't be square \n"
  "You wanna battle me -- Anytime, anywhere \n"
  "\n"
  "You thought that I was weak, Boy, you're dead wrong \n"
  "So come on, everybody and sing this song \n"
  "\n"
  "Say -- Play that funky music Say, go white boy, go white boy go \n"
  "play that funky music Go white boy, go white boy, go \n"
  "Lay down and boogie and play that funky music till you die. \n"
  "\n"
  "Play that funky music Come on, Come on, let me hear \n"
  "Play that funky music white boy you say it, say it \n"
  "Play that funky music A little louder now \n"
  "Play that funky music, white boy Come on, Come on, Come on \n"
  "Play that funky music \n">>.
