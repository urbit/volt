::
:: sur/volt.hoon
::
|%
::
+$  pubkey  octs
+$  txid    octs
+$  sats    @ud
+$  chan-id  @ud
+$  htlc-id  @ud
+$  circuit-key
  $:  =chan-id
      =htlc-id
  ==
+$  hash      octs
+$  preimage  octs
::
++  rpc
  |%
  +$  action
    $%  [%get-info ~]
        [%open-channel node=pubkey local-amount=sats push-amount=sats]
        [%close-channel funding-txid=txid output-index=@ud]
        [%settle-htlc =circuit-key preimage=octs]
        [%fail-htlc =circuit-key]
    ==
  ::
  +$  result
    $%  [%get-info version=@t commit-hash=@t identity-pubkey=pubkey]
        [%open-channel channel-point]
        [%close-channel ~]
        [%settle-htlc =circuit-key]
        [%fail-htlc =circuit-key]
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
        =chan-id
        fee-base-msat=@ud
        fee-proportional-usat=@ud
        cltv-expiry-delta=@ud
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
        remote-pubkey=pubkey
        channel-point=@t
        =chan-id
        capacity=sats
        local-balance=sats
        remote-balance=sats
        commit-fee=sats
        total-sent=sats
    ==
  ::
  +$  channel-close-summary
    $:  channel-point=@t
        =chan-id
        chain-hash=@t
        closing-tx-hash=@t
        remote-pubkey=pubkey
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
  +$  htlc-intercept-request
    $:  incoming-circuit-key=circuit-key
        incoming-amount-msat=sats
        incoming-expiry=@ud
        payment-hash=octs
        outgoing-requested-chan-id=chan-id
        outgoing-amount-msat=sats
        outgoing-expiry=@ud
        onion-blob=octs
    ==
  ::
  +$  htlc-intercept-response
    $:  incoming-circuit-key=circuit-key
        action=htlc-action
        preimage=(unit octs)
    ==
  ::
  +$  htlc-action
    $?  %'SETTLE'
        %'FAIL'
        %'RESUME'
    ==
  --
::
::  provider types
::
++  provider
  |%
  ::
  +$  host-info
    $:  api-url=@t
        connected=?
        clients=(set ship)
    ==
  ::
  +$  channel-info
    $:  =chan-id
        active=?
        remote-pubkey=pubkey
    ==
  ::
  +$  htlc
    $:  =circuit-key
        =hash
    ==
  +$  htlcs  (map circuit-key htlc)
  ::
  +$  command
    $%  [%set-url api-url=@t]
        [%open-channel to=pubkey local-amt=sats push-amt=sats]
        [%close-channel funding-txid=txid output-index=@ud]
    ==
  ::
  +$  action
    $%  [%ping ~]
        [%settle-htlc =circuit-key preimage=octs]
        [%fail-htlc =circuit-key]
    ==
  ::
  +$  result
    $%  [%htlc payment-hash=octs]
    ==
  ::
  +$  error
    $%  [%rpc-error error:rpc]
        [%not-connected ~]
        [%bad-request ~]
    ==
  ::
  +$  update  (each result error)
  ::
  +$  status
    $%  [%connected ~]
        [%disconnected ~]
    ==
  --
::
::  client types
::
++  client
  |%
  --
--
