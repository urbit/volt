::
::  lib/volt.hoon
::
/-  spider, volt=volt
/+  *strandio
=,  strand=strand:spider
|%
++  rpc
  |_  =config:provider:volt
  ::
  ++  action-to-json
    |=  act=action:rpc:volt
    =,  enjs:format
    |^  ^-  json
    ?+    -.act  ~|("Unknown request type" !!)
        %open-channel
      (open-channel +.act)
    ::
        %send-payment
      (send-payment +.act)
    ::
    ==
    ++  open-channel
      |=  [=pubkey:volt local-amt=sats:volt push-amt=sats:volt]
      ^-  json
      %-  pairs
      :~  ['node_pubkey' [%s (en:base64:mimes:html pubkey)]]
          ['local_funding_amount' (numb local-amt)]
          ['push_sat' (numb push-amt)]
      ==
    ::
    ++  send-payment
      |=  =invoice:rpc:volt
      ^-  json
      %-  pairs
      :~  ['dest' [%s (en:base64:mimes:html pubkey.invoice)]]
          ['amt' (numb amount.invoice)]
          ['payment_hash' [%s (en:base64:mimes:html r-hash.invoice)]]
          ['final_cltv_delta' (numb 0)]
      ==
    --
  ::
  ++  action-to-request
    |=  act=action:rpc:volt
    |^  ^-  request:http
    ?-    -.act
        %get-info
      %-  get-request
      (url '/v1/getinfo' '')
    ::
        %open-channel
      (post-request (url '/v1/channels' '') act)
    ::
        %close-channel
      %-  delete-request
      (url '/v1/channels/' (en:base64:mimes:html chid.act))
    ::
        %send-payment
      (post-request (url '/v2/router/send' '') act)
    ::
    ==
    ++  url
      |=  [route=@t params=@t]
      %^  cat  3
      (cat 3 uri.config route)  params
    ::
    ++  get-request
      |=  url=@t
      ^-  request:http
      [%'GET' url ~[['Grpc-Metadata-Macaroon' macaroon.config]] ~]
    ::
    ++  delete-request
      |=  url=@t
      ^-  request:http
      [%'DELETE' url ~[['Grpc-Metadata-Macaroon' macaroon.config]] ~]
    ::
    ++  post-request
      |=  [url=@t act=action:rpc:volt]
      ^-  request:http
      :*  %'POST'
          url
          :~  ['Grpc-Metadata-Macaroon' macaroon.config]
              ['Content-Type' 'application/json']
          ==
          =,  html
          %-  some
          %-  as-octt:mimes
          %-  en-json
          (action-to-json act)
      ==
    --
  ::
  ++  result-from-json
    |=  [act=action:rpc:volt jon=json]
    =,  dejs:format
    |^  ^-  result:rpc:volt
    ?-    -.act
        %get-info
      =/  info=[version=@t hash=@t pubkey=@t]
      %.  jon  node-info
      [%get-info version.info hash.info (as-octs:mimes:html pubkey.info)]
    ::
        %open-channel
      =/  res=[txid=@t oidx=@ud]
      %.  jon   open-channel-response
      =/  txid  (de:base64:mimes:html txid.res)
      =/  txid  (need txid)
      [%open-channel funding-txid=txid index=oidx.res]
    ::
        %close-channel
      [%close-channel ~]
    ::
        %send-payment
      [%send-payment ~]
    ==
    ++  node-info
      %-  ot
      :~  [%version so]
          ['commit_hash' so]
          ['identity_pubkey' so]
      ==
    ::
    ++  open-channel-response
      %-  ot
      :~  ['funding_txid_bytes' so]
          ['output_index' ni]
      ==
    --
  ::
  ++  error-from-json
    |=  jon=json
    ^-  error:rpc:volt
    =,  dejs:format
    %.  jon
    %-  ot
    :~  [%code ni]
        [%message so]
    ==
  ::
  ++  status-code
    |=  =client-response:iris
    =/  m  (strand ,@ud)
    ^-  form:m
    ?>  ?=(%finished -.client-response)
    (pure:m status-code.response-header.client-response)
  ::
  ++  send
    |=  act=action:rpc:volt
    =/  m              (strand ,response:rpc:volt)
    =/  =request:http  (action-to-request act)
    ^-  form:m
    ;<  ~                      bind:m  (send-request request)
    ;<  =client-response:iris  bind:m  take-client-response
    ;<  status=@ud             bind:m  (status-code client-response)
    ;<  body=@t                bind:m  (extract-body client-response)
    =/  jon=(unit json)  (de-json:html body)
    ?~  jon  (strand-fail:strand %json-parse-error ~)
    %-  pure:m
      ?:  =(status 200)
        [%& (result-from-json act u.jon)]
        [%| (error-from-json u.jon)]
  --
::
--
