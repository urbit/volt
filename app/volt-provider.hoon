::
/-  volt
/+  server, default-agent, dbug, libvolt=volt
=,  provider:volt
|%
+$  card  card:agent:gall
::
+$  versioned-state
  $%  state-0
  ==
::
+$  state-0
  $:  %0
      =host-info
      channels=(map chan-id channel-info)
      htlcs=(map circuit-key htlc)
  ==
--
::
%-  agent:dbug
::
=|  state-0
=*  state  -
^-  agent:gall
=<
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %|) bowl)
    hc    ~(. +> bowl)
::
++  on-init
  |^  ^-  (quip card _this)
  ~&  >  '%volt-provider initialized successfully'
  :_  this(host-info default-host-info)
  :~  [%pass /bind %arvo %e %connect [~ /'~volt-channels'] %volt-provider]
      [%pass /bind %arvo %e %connect [~ /'~volt-htlcs'] %volt-provider]
  ==
  ++  default-host-info
    :*  api-url=''
        connected=%.n
        clients=*(set ship)
    ==
  --
::
++  on-save
  ^-  vase
  !>(state)
::
++  on-load
  |=  old-state=vase
  ^-  (quip card _this)
  ~&  >  '%volt-provider recompiled successfully'
  `this(state !<(versioned-state old-state))
::
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  =^  cards  state
  ?+    mark  (on-poke:def mark vase)
      %volt-provider-command
    ?>  (team:title our.bowl src.bowl)
    (handle-command:hc !<(command:provider:volt vase))
  ::
      %volt-provider-action
    (handle-action:hc !<(action:provider:volt vase))
  ::
      %handle-http-request
    (handle-request:hc !<([id=@ta =inbound-request:eyre] vase))
  ==
  [cards this]
::
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  ?:  ?=(%eyre -.sign-arvo)
    `this
  ?:  ?=([%ping-timer *] wire)
    [do-ping:hc this]
  (on-arvo:def wire sign-arvo)
::
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?:  ?=([%http-response *] path)
    `this
  (on-watch:def path)
::
++  on-agent
  |=  [=wire =sign:agent:gall]
  ^-  (quip card _this)
  ?+    -.wire  (on-agent:def wire sign)
      %thread
    ?+    -.sign  (on-agent:def wire sign)
        %poke-ack
      ?~  p.sign
        `this
      %-  (slog leaf+"Thread failed!" u.p.sign)
      `this
    ::
        %fact
      ?+    p.cage.sign  (on-agent:def wire sign)
          %thread-fail
        =/  err  !<  (pair term tang)  q.cage.sign
        %-  (slog leaf+"Thread failed: {(trip p.err)}" q.err)
        `this
      ::
          %thread-done
        =^  cards  state
          %+  handle-rpc-response:hc  +.wire
          !<(response:rpc:volt q.cage.sign)
        [cards this]
      ==
    ==
  ==
::
++  on-peek   on-peek:def
++  on-leave  on-leave:def
++  on-fail   on-fail:def
--
::
|_  =bowl:gall
++  handle-action
  |=  =action:provider:volt
  ^-  (quip card _state)
  ?.  ?|(connected.host-info ?=(%ping -.action))
    ~&  >>>  "not connected to LND"
    `state
  =/  cards=(list card)
    ?-    -.action
        %ping
      %-  do-rpc  [%get-info ~]
    ::
        %settle-htlc
      %+  settle-htlc  circuit-key.action  preimage.action
    ::
        %fail-htlc
      %-  do-rpc  [%fail-htlc +.action]
  ==
  [cards state]
::
++  settle-htlc
  |=  [=circuit-key =preimage]
  ^-  (list card)
  %+  fall
    %+  bind  (~(get by htlcs.state) circuit-key)
    |=  =htlc
    %-  do-rpc  (settle-htlc-action htlc preimage)
  ~|("unknown htlc: {<circuit-key>}" ~)
::
++  settle-htlc-action
  |=  [=htlc =preimage]
  ^-  action:rpc:volt
  ?.  =((sha-256l:sha preimage) hash.htlc)
    ~&  >>>  "Incorrect preimage for HTLC: {<circuit-key.htlc>}"
    [%fail-htlc circuit-key.htlc]
  [%settle-htlc circuit-key.htlc preimage]
::
++  handle-command
  |=  =command
  |^  ^-  (quip card _state)
  ?-    -.command
      %set-url
    :-  do-ping
    state(host-info (mk-host-info api-url.command))
  ::
      %open-channel
    :-  (do-rpc [%open-channel +.command])
    state
  ::
      %close-channel
    :-  (do-rpc [%close-channel +.command])
    state
  ==
  ++  mk-host-info
    |=  url=@t
    :*  api-url=url
        connected=%.n
        clients=*(set ship)
    ==
  --
::
++  do-rpc
  |=  =action:rpc:volt
  ^-  (list card)
  =/  tid     `@ta`(cat 3 'thread_' (scot %uv (sham eny.bowl)))
  =/  args     [~ `tid %lnd-rpc !>([~ host-info.state action])]
  =/  wire     (rpc-wire action)
  :~  [%pass wire %agent [our.bowl %spider] %watch /thread-result/[tid]]
      [%pass wire %agent [our.bowl %spider] %poke %spider-start !>(args)]
  ==
::
++  rpc-wire
  |=  =action:rpc:volt
  ^-  wire
  =/  ta-now  `@ta`(scot %da now.bowl)
  /thread/[-.action]/[ta-now]
::
++  no-content
  |=  id=@ta
  ^-  (list card)
  :~  [%give %fact ~[/http-response/[id]] [%http-response-header !>([201 ~])]]
      [%give %kick ~[/http-response/[id]] ~]
  ==
::
++  request-json
  |=  =request:http
  ^-  (unit json)
  %+  biff  body.request
    |=  =octs
    =/  body=@t  +.octs
    (de-json:html body)
::
++  handle-request
  |=  [id=@ta =inbound-request:eyre]
  ^-  (quip card _state)
  %+  fall
    %+  bind  (request-json request.inbound-request)
    |=  =json
    ?:  =(url.request.inbound-request '/~volt-channels')
      %+  update-channel  id
      %-  channel-update:dejs:rpc:libvolt
      json
    ::
    ?>  =(url.request.inbound-request '/~volt-htlcs')
      %+  handle-htlc  id
      %-  htlc-intercept-request:dejs:rpc:libvolt
      json
  [(no-content id) state]
::
++  update-channel
  |=  [id=@ta =channel-update:rpc:volt]
  ^-  (quip card _state)
  ?-    -.channel-update
      %open-channel
    ~&  >  "open channel: {<chan-id.channel-update>}"
    =/  =chan-id  chan-id.channel-update
    =/  =channel-info
      :*  chan-id=chan-id
          active=active.channel-update
          remote-pubkey=remote-pubkey.channel-update
      ==
    :-  (no-content id)
    state(channels (~(put by channels.state) chan-id channel-info))
  ::
      %closed-channel
    ~&  >  "channel closed: {<chan-id.channel-update>}"
    :-  (no-content id)
    state(channels (~(del by channels.state) chan-id.channel-update))
  ::
      %active-channel
    =/  =txid   funding-txid.channel-update
    =/  ix=@ud  output-index.channel-update
    ~&  >  "active channel: {<txid>}:{<ix>}"
    [(no-content id) state]
  ::
      %inactive-channel
    =/  =txid   funding-txid.channel-update
    =/  ix=@ud  output-index.channel-update
    ~&  >  "inactive channel: {<txid>}:{<ix>}"
    [(no-content id) state]
  ::
      %pending-channel
    =/  =txid   txid.channel-update
    =/  ix=@ud  output-index.channel-update
    ~&  >  "pending channel: {<txid>}:{<ix>}"
    [(no-content id) state]
  ==
::
++  handle-htlc
  |=  [id=@ta req=htlc-intercept-request:rpc:volt]
  ^-  (quip card _state)
  =/  =circuit-key  incoming-circuit-key.req
  =/  =htlc
    :*  circuit-key=circuit-key
        hash=payment-hash.req
    ==
  :-  (no-content id)
  state(htlcs (~(put by htlcs.state) circuit-key htlc))
::
++  handle-rpc-response
  |=  [=wire =response:rpc:volt]
  ^-  (quip card _state)
  ?-  -.response
    %&  (handle-rpc-result wire +.response)
    %|  (handle-rpc-error wire +.response)
  ==
::
++  handle-rpc-result
  |=  [=wire =result:rpc:volt]
  ^-  (quip card _state)
  ?+    -.wire  ~|("Unexpected RPC result" !!)
      %get-info
    ?>  ?=([%get-info *] result)
    `state(connected.host-info %.y)
  ::
      %open-channel
    ?>  ?=([%open-channel *] result)
    ~&  >  "opening channel: funding-txid={<funding-txid.result>}"
    `state
  ::
      %close-channel
    ?>  ?=([%close-channel *] result)
    `state
  ::
      %settle-htlc
    ?>  ?=([%settle-htlc *] result)
    =.  htlcs.state  (~(del by htlcs.state) circuit-key.result)
    ~&  >  "settled HTLC: {<circuit-key.result>}"
    `state
  ::
      %fail-htlc
    ?>  ?=([%fail-htlc *] result)
    =.  htlcs.state  (~(del by htlcs.state) circuit-key.result)
    ~&  >>>  "failed HTLC: {<circuit-key.result>}"
    `state
  ==
::
++  handle-rpc-error
  |=  [=wire =error:rpc:volt]
  ^-  (quip card _state)
  %-  (slog leaf+"RPC Error: {(trip message.error)}" ~)
  `state
::
++  is-channel-active
  |=  =chan-id
  %+  fall
  %+  bind  (~(get by channels.state) chan-id)
    |=  =channel-info  active.channel-info
  %.n
::
++  is-client-htlc
  |=  [=ship =circuit-key]
  %.n
::
++  is-client-channel
  |=  [=ship =chan-id]
  %.n
::
++  is-client
  |=  user=ship
  (~(has in clients.host-info) user)
::
++  start-ping-timer
  |=  interval=@dr
  ^-  card
  [%pass /ping-timer %arvo %b %wait (add now.bowl interval)]
::
++  do-ping
  ^-  (list card)
  =/  =action:provider  [%ping ~]
  :~  :*  %pass  /ping/[(scot %da now.bowl)]  %agent
          [our.bowl %volt-provider]  %poke
          %volt-provider-action  !>(action)
      ==
      (start-ping-timer ~s30)
  ==
--
