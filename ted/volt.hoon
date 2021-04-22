::
/-  spider, v=volt
/+  *strandio, volt
=,  strand=strand:spider
=>
|%
++  uri  'http://127.0.0.1:8080'
::
++  macaroon  '0201036c6e640224030a108fb512dac6c5b9580d7304292750c22f1201301a0c0a04696e666f120472656164000006201ca09ac37e0e48fedcad5daffe4baf71bd61a83636264ffe447c633961f4baec'
::
++  config  (config:provider:v uri=uri macaroon=macaroon)
::
++  rpc-call
  |=  action=action:rpc:provider:v
  =/  =request:http  (to-request:rpc:volt config action)
  =/  m  (strand ,json)
  ^-  form:m
  ;<  ~                      bind:m  (send-request request)
  ;<  =client-response:iris  bind:m  take-client-response
  ;<  body=@t                bind:m  (extract-body client-response)
  =/  json=(unit json)
    %-  de-json:html  body
  ?~  json
    (strand-fail %json-parse-error ~)
  (pure:m u.json)
--
::
^-  thread:spider
|=  arg=vase
=/  action   (rpc-call (action:rpc:provider:v [%get-info ~]))
=/  m        (strand ,vase)
;<  js=json  bind:m  action
=/  rs=node-info:rpc:provider:v
  (node-info:from-json:rpc:volt js)
%-  (slog leaf+"Version: {(trip version.rs)}" ~)
(pure:m !>(~))
