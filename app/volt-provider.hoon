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
  ^-  (quip card _this)
  ~&  >  '%volt-provider initialized successfully'
  :_  this(host-info ['' %.n *(set ship)])
  :~  [%pass /bind %arvo %e %connect [~ /'~volt-channels'] %volt-provider]
      [%pass /bind %arvo %e %connect [~ /'~volt-htlcs'] %volt-provider]
  ==
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
    ?>  (team:title our.bowl src.bowl)
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
  ?+    -.path  (on-watch:def path)
      %http-response
    `this
  ==
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
++  on-peek
  |=  =path
  ^-  (unit (unit cage))
  (on-peek:def path)
::
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
  ?-    -.action
      %ping
    [(do-rpc [%get-info ~]) state]
  ::
      %settle-htlc
    :_  state
    (do-rpc [%settle-htlc circuit-key.htlc-info.action preimage.action])
  ::
      %fail-htlc
    :_  state
    (do-rpc [%fail-htlc circuit-key.htlc-info.action])
  ==
::
++  handle-command
  |=  =command
  ^-  (quip card _state)
  ?-    -.command
      %set-url
    :-  do-ping
    state(host-info [api-url.command %.n *(set ship)])
  ::
      %open-channel
    [(do-rpc [%open-channel +.command]) state]
  ::
      %close-channel
    [(do-rpc [%close-channel +.command]) state]
  ==
::
++  handle-request
  |=  [id=@ta =inbound-request:eyre]
  |^  ^-  (quip card _state)
  %+  fall
    %+  bind  (request-json request.inbound-request)
    |=  =json
    ?:  =(url.request.inbound-request '/~volt-channels')
      %+  handle-channel-update  id
      %-  channel-update:dejs:rpc:libvolt
      json
    ::
    ?>  =(url.request.inbound-request '/~volt-htlcs')
      %+  handle-htlc-intercept  id
      %-  htlc-intercept-request:dejs:rpc:libvolt
      json
  [(no-content id) state]
  ::
  ++  request-json
    |=  =request:http
    ^-  (unit json)
    %+  biff  body.request
      |=  =octs
      =/  body=@t  +.octs
      (de-json:html body)
  --
::
++  handle-channel-update
  |=  [id=@ta =channel-update:rpc:volt]
  ^-  (quip card _state)
  ?-    -.channel-update
      %open-channel
    ~&  >  "open channel: {<chan-id.channel-update>}"
    [(no-content id) state]
  ::
      %closed-channel
    ~&  >  "channel closed: {<chan-id.channel-update>}"
    [(no-content id) state]
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
++  handle-htlc-intercept
  |=  [id=@ta req=htlc-intercept-request:rpc:volt]
  ^-  (quip card _state)
  =/  =htlc-info
    :*  circuit-key=incoming-circuit-key.req
        hash=payment-hash.req
        chan-id=outgoing-requested-chan-id.req
    ==
  :_  state
  [(poke-manager /htlc [%settle-htlc htlc-info]) (no-content id)]
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
    ~&  >  "settled HTLC: {<circuit-key.result>}"
    `state
  ::
      %fail-htlc
    ?>  ?=([%fail-htlc *] result)
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
++  poke-manager
  |=  [=path =action:volt]
  ^-  card
  :*  %pass   path
      %agent  [our.bowl %volt]
      %poke   %volt-action  !>(action)
  ==
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
