:: lib/volt.hoon
/-  volt
|%
++  rpc
  =,  provider:volt
  =,  dejs:format
  |%
  ++  from-json
    |%
    ::
    ++  node-info
      %-  ot
      :~  [%version so]
          ['commit_hash' so]
      ==
    --
  ::
  ++  to-request
    |=  [conf=config act=action:rpc]
    |^  ^-  request:http
    ?-    -.act
        %get-info
      %-  get-request
      (make-url '/v1/getinfo' '')
      ::
        %open-channel
      %-  get-request
      (make-url '/v1/openchannel' '')
      ::
        %close-channel
      %-  get-request
      (make-url '/v1/closechannel' '')
      ::
        %send-payment
      %-  get-request
      (make-url '/v1/sendpayment' '')
    ==
    ::
    ++  make-url
      |=  [route=@t params=@t]
      %^  cat  3
      (cat 3 uri.conf route)  params
    ::
    ++  get-request
      |=  url=@t
      ^-  request:http
      [%'GET' url ~[['Grpc-Metadata-Macaroon' macaroon.conf]] ~]
    --
  --
--
