::
/-  volt
/+  server, default-agent, dbug, libvolt=volt
|%
+$  card  card:agent:gall
::
+$  versioned-state
  $%  state-0
  ==
::
+$  state-0
  $:  %0
      =config:provider:volt
      pending-htlcs=(set circuit-key:rpc:volt)
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
  :_  this
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
  =/  old  !<(versioned-state old-state)
  ?-    -.old
      %0
    `this(state old)
  ==
::
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  =^  cards  state
  ?+    mark  (on-poke:def mark vase)
      %volt-action
    (handle-action:hc !<(action:provider:volt vase))
  ::
      %volt-command
    (handle-command:hc !<(command:provider:volt vase))
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
  (on-arvo:def wire sign-arvo)
::
++  on-watch
  |=  =path
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
        %-  (slog leaf+"Thread started!" ~)
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
  ?-    -.action
      %open-channel   `state
      %close-channel  `state
      %preimage       `state
  ==
::
++  handle-command
  |=  =command:provider:volt
  ^-  (quip card _state)
  ?>  (team:title our.bowl src.bowl)
  ?-    -.command
      %set-configuration
    =.  config.state  config.command
    `state
  ::
      %ping
    :_  state
    (start-rpc-thread [%get-info ~])
  ::
      %open-channel
    :_  state
    (start-rpc-thread [%open-channel +.command])
  ::
      %close-channel
    :_  state
    (start-rpc-thread [%close-channel +.command])
  ==
::
++  start-rpc-thread
  |=  =action:rpc:volt
  ^-  (list card)
  =/  tid     `@ta`(cat 3 'thread_' (scot %uv (sham eny.bowl)))
  =/  args     [~ `tid %lnd-rpc !>([~ config.state action])]
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
      %-  forward-htlc-intercept-request:dejs:rpc:libvolt
      json
  [(no-content id) state]
::
++  update-channel
  |=  [id=@ta =channel-update:rpc:volt]
  ^-  (quip card _state)
  ?-    -.channel-update
      %open-channel
    [(no-content id) state]
  ::
      %closed-channel
    [(no-content id) state]
  ::
      %active-channel
    [(no-content id) state]
  ::
      %inactive-channel
    [(no-content id) state]
  ::
      %pending-channel
    [(no-content id) state]
  ==
::
++  handle-htlc
  |=  [id=@ta htlc=forward-htlc-intercept-request:rpc:volt]
  ^-  (quip card _state)
  =/  =circuit-key         incoming-circuit-key.htlc
  =.  pending-htlcs.state  (~(put in pending-htlcs.state) circuit-key)
  :_  state
  (no-content id)
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
    `state
  ::
      %open-channel
    ?>  ?=([%open-channel *] result)
    `state
  ::
      %close-channel
    ?>  ?=([%close-channel *] result)
    `state
  ::
      %send-payment
    ?>  ?=([%send-payment *] result)
    `state
  ::
      %settle-htlc
    ?>  ?=([%settle-htlc *] result)
    `state
  ::
      %fail-htlc
    ?>  ?=([%fail-htlc *] result)
    `state
  ==
::
++  handle-rpc-error
  |=  [=wire =error:rpc:volt]
  ^-  (quip card _state)
  %-  (slog leaf+"RPC Error: {(trip message.error)}" ~)
  `state
--
