:: volt.hoon
::
|%
++  provider
  |%
  +$  id  @t
  +$  config
    $:  uri=@t
        macaroon=@t
    ==
  ::
  +$  command
    $%  [%set-uri uri=@t]
        [%set-macaroon @ta]
    ==
  ::
  +$  action
    $%  [%ping ~]
        [%open-channel node-key=@t local-amt=@ud push-amt=@ud]
        [%close-channel =id]
        [%close-all-channels]
        [%channel-balance =id]
    ==
  ::
  ++  rpc
    |%
    +$  chain
      $:  chain=@t
          net=@t
      ==
    ::
    +$  node-info
      $:  version=@t
          commit-hash=@t
          :: identity-pubkey=@t
          :: alias=@t
          :: color=@t
          :: num-pending-channels=@sd
          :: num-active-channels=@sd
          :: num-inactive-channels=@sd
          :: num-peers=@sd
          :: block-height=@sd
          :: block-hash=@t
          :: best-header-timestamp=@t
          :: synced-to-chain=?
          :: synced-to-graph=?
          :: testnet=?
          :: chains=(list chain)
          :: uris=(list @t)
          :: features=@
      ==
    ::
    +$  htlc
      $:  incoming=?
          amount=@t
          hash-lock=@ub
          expiration-height=@sd
          htlc-index=@t
          forwarding-channel=@t
          forwarding-htlc-index=@t
      ==
    ::
    +$  channel
      $:  active=?
          remote-pubkey=@t
          channel-point=@t
          chan-id=@t
          capacity=@t
          local-balance=@t
          remote-balance=@t
          commit-fee=@t
          commit-weight=@t
          fee-per-kw=@t
          unsettled-balance=@t
          total-satoshis-sent=@t
          total-satoshis-received=@t
          num-updates=@t
          pending-htlcs=(list htlc)
          csv-delay=@sd
          private=?
          initiator=?
          status-flags=@t
          local-chan-reserev-sat=@t
          remote-chan-reserve-sat=@t
          static-remote-key=?
          =commitment-type
          lifetime=@t
          uptime=@t
          close-address=@t
          push-amount-sat=@t
          thaw-height=@sd
          local-constraints=channel-constraints
          remote-constraints=channel-constraints
      ==
    ::
    +$  commitment-type  @ud
    ::
    +$  channel-constraints
      $:  csv-delay=@ud
          chan-reserve-sat=@ud
          dust-limit-sat=@ud
          max-pending-amt-msat=@ud
          min-htlc-msat=@ud
          max-accepted-htlcs=@ud
      ==
    ::
    +$  circuit-key
      $:  chan-id=@udG
          htlc-id=@udG
      ==
    ::
    ::  +$  payment  ?
    ::
    +$  action
      $%  [%get-info ~]
          [%open-channel ~]
          [%close-channel ~]
          [%send-payment ~]
      ==
    ::
    +$  result
      $%  [%get-info =node-info]
      ==
  --
--
::
++  user
  |%
  +$  config
    $:  provider=@p
    ==
  --
--
