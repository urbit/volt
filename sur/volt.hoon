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
        [%open-channel funding-txid=txid index=@ud]
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
    $%  [%set-configuration =config]
        [%ping ~]
    ==
  ::
  +$  action
    $%  [%associate-pubkey =ship =pubkey]
        [%open-channel to=channel-counterparty local-amt=sats push-amt=sats]
        [%close-channel =chid]
    ==
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
