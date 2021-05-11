::
:: sur/volt.hoon
::
|%
::
+$  pubkey  octs
+$  txid  octs
+$  chid  octs
+$  sats  @ud
::
+$  channel-counterparty
  $%  [%ship ship]
      [%pubkey pubkey]
  ==
::
++  rpc
  |%
  +$  action
    $%  [%get-info ~]
        [%open-channel node=pubkey local-amount=sats push-amount=sats]
        [%close-channel =chid]
        [%send-payment =invoice]
    ==
  ::
  +$  result
    $%  [%get-info version=@t commit-hash=@t identity-pubkey=pubkey]
        [%open-channel channel-point]
        [%close-channel ~]
        [%send-payment ~]
    ==
  ::
  +$  error
    $:  code=@ud
        message=@t
    ==
  ::
  +$  response  (each result error)
  ::
  +$  route-hint
    $:  node-id=pubkey
        chan-id=chid
        fee-base-msat=@ud
        fee-proportional-usat=@ud
        cltv-expiry-delta=@ud
    ==
  ::
  +$  invoice
    $:  memo=@t
        r-primage=octs
        r-hash=octs
        =pubkey
        amount=sats
    ==
  ::
  +$  channel-update
    $%  [%open-channel channel]
        [%closed-channel channel-close-summary]
        [%active-channel channel-point]
        [%inactive-channel channel-point]
        [%pending-channel pending-channel]
    ==
  ::
  +$  channel
    $:  active=?
        remote-pubkey=@t
        channel-point=@t
        chan-id=@t
        capacity=sats
        local-balance=sats
        remote-balance=sats
        commit-fee=sats
        total-sent=sats
    ==
  ::
  +$  channel-close-summary
    $:  channel-point=@t
        chid=@t
        chain-hash=@t
        closing-tx-hash=@t
        remote-pubkey=@t
        channel-closure-type=@tas
    ==
  ::
  +$  channel-point
    $:  funding-txid=txid
        output-index=@ud
    ==
  ::
  +$  pending-channel
    $:  =txid
        output-index=@ud
    ==
  ::
  +$  forward-htlc-intercept-request
    $:  incoming-circuit-key=circuit-key
        incoming-amount-msat=sats
        incoming-expiry=@ud
        payment-hash=octs
        outgoing-requested-chan-id=@ud
        outgoing-amount-msat=sats
        outgoing-expiry=@ud
        custom-records=(list custom-record-entry)
        onion-blob=octs
    ==
  ::
  +$  custom-record-entry
    $:  key=@ud
        value=octs
    ==
  ::
  +$  circuit-key
    $:  chan-id=@ud
        htlc-id=@ud
    ==
  ::
  +$  forward-htlc-intercept-response
    $:  incoming-circuit-key=circuit-key
        action=resolve-hold-forward-action
        preimage=octs
    ==
  ::
  +$  resolve-hold-forward-action
    $%  %settle
        %fail
        %resume
    ==
  --
::
::  provider types
::
++  provider
  |%
  +$  config
    $:  uri=@t
        macaroon=@t
    ==
  ::
  +$  command
    $%  [%ping ~]
        [%set-configuration =config]
        [%open-channel to=pubkey local-amt=sats push-amt=sats]
        [%close-channel =chid]
    ==
  ::
  +$  action
    $%  [%open-channel to=channel-counterparty local-amt=sats push-amt=sats]
        [%close-channel =chid]
    ==
  ::
  --
::
::  client types
::
+$  config
  $:  provider=ship
  ==
::
+$  action
  $%  [%set-provider provider=ship]
      [%open-channel ~]
      [%send-payment to=channel-counterparty value=sats]
      [%send-invoice ~]
  ==
::
--
