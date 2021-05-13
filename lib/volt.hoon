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
  ++  enjs
    =,  enjs:format
    |%
    ++  action
      |=  act=action:rpc:volt
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
    ++  forward-htlc-intercept-response
      |=  resp=forward-htlc-intercept-response:rpc:volt
      |^  ^-  json
      %-  pairs
      :~  ['incoming_circuit_key' (circuit-key incoming-circuit-key.resp)]
          ['action' [%s action.resp]]
          ['preimage' [%s (en:base64:mimes:html preimage.resp)]]
      ==
      ++  circuit-key
        |=  =circuit-key:rpc:volt
        %-  pairs
        :~  ['chan_id' (numb chan-id.circuit-key)]
            ['htlc_id' (numb htlc-id.circuit-key)]
        ==
      --
    --
  ::
  ++  dejs
    =,  dejs:format
    |%
    ++  channel-update
      |=  =json
      |^  ^-  channel-update:rpc:volt
      ?+    (update-type json)  ~|('Unknown update type' !!)
          %'OPEN_CHANNEL'
        [%open-channel (open-channel json)]
      ::
          %'CLOSED_CHANNEL'
        [%closed-channel (closed-channel json)]
      ::
          %'ACTIVE_CHANNEL'
        [%active-channel (active-channel json)]
      ::
          %'INACTIVE_CHANNEL'
        [%inactive-channel (inactive-channel json)]
      ::
          %'PENDING_OPEN_CHANNEL'
        [%pending-channel (pending-channel json)]
      ==
      ++  update-type
        %-  ot  ~[['type' so]]
      ::
      ++  channel-data
        |*  [k=cord a=fist]
        %-  ot  ~[[k a]]
      ::
      ++  active-channel
        %+  channel-data  'active_channel'
        %-  ot
        :~  ['funding_txid_bytes' (su parse:base64:mimes:html)]
            ['output_index' ni]
        ==
      ::
      ++  inactive-channel
        %+  channel-data  'inactive_channel'
        %-  ot
        :~  ['funding_txid_bytes' (su parse:base64:mimes:html)]
            ['output_index' ni]
        ==
      ::
      ++  closed-channel
        %+  channel-data  'closed_channel'
        %-  ot
        :~  ['channel_point' so]
            ['chan_id' so]
            ['chain_hash' so]
            ['closing_tx_hash' so]
            ['remote_pubkey' so]
            ['close_type' so]
        ==
      ::
      ++  pending-channel
        %+  channel-data  'pending_open_channel'
        %-  ot
        :~  ['txid' (su parse:base64:mimes:html)]
            ['output_index' ni]
        ==
      ::
      ++  open-channel
        %+  channel-data  'open_channel'
        %-  ot
        :~  ['active' bo]
            ['remote_pubkey' so]
            ['channel_point' so]
            ['chan_id' so]
            ['capacity' (su dim:ag)]
            ['local_balance' (su dim:ag)]
            ['remote_balance' (su dim:ag)]
            ['commit_fee' (su dim:ag)]
            ['total_satoshis_sent' (su dim:ag)]
        ==
      --
    ::
    ++  forward-htlc-intercept-request
      |=  =json
      |^  ^-  forward-htlc-intercept-request:rpc:volt
      %.  json
      %-  ot
      :~  ['incoming_circuit_key' circuit-key]
          ['incoming_amount_msat' ni]
          ['incoming_expiry' ni]
          ['payment_hash' (su parse:base64:mimes:html)]
          ['outgoing_requested_chan_id' ni]
          ['outgoing_amount_msat' ni]
          ['outgoing_expiry' ni]
          ['custom_records' (ar custom-record)]
          ['onion_blob' (su parse:base64:mimes:html)]
      ==
      ++  circuit-key
        %-  ot
        :~  ['chan_id' ni]
            ['htlc_id' ni]
        ==
      ::
      ++  custom-record
        %-  ot
        :~  ['key' ni]
            ['value' (su parse:base64:mimes:html)]
        ==
      --
    ::
    ++  result
      |=  [act=action:rpc:volt jon=json]
      |^  ^-  result:rpc:volt
      ?-    -.act
          %get-info
        =/  info=[version=@t hash=@t pubkey=@t]
        %.  jon  node-info
        [%get-info version.info hash.info (as-octs:mimes:html pubkey.info)]
      ::
          %open-channel
        [%open-channel (channel-point jon)]
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
      ++  channel-point
        %-  ot
        :~  ['funding_txid_bytes' (su parse:base64:mimes:html)]
            ['output_index' ni]
        ==
      --
    ::
    ++  error
      |=  jon=json
      ^-  error:rpc:volt
      %.  jon
      %-  ot
      :~  [%code ni]
          [%message so]
      ==
    --
  ::
  ++  action-to-request
    |=  act=action:rpc:volt
    |^  ^-  request:http
    ?-    -.act
        %get-info
      %-  get-request
      (url '/getinfo' '')
    ::
        %open-channel
      (post-request (url '/channels' '') act)
    ::
        %close-channel
      =/  txid=@t  (en:base64:mimes:html funding-txid.act)
      =/  oidx=@t  (scot %ud output-index.act)
      =/  parms    (cat 3 (cat 3 txid '/') oidx)
      %-  delete-request
      (url '/channels/' parms)
    ::
        %send-payment
      (post-request (url '/send_payment' '') act)
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
          (action:enjs act)
      ==
    --
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
        [%& (result:dejs act u.jon)]
        [%| (error:dejs u.jon)]
  --
::
++  provider
  |%
  --
--
