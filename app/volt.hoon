::
/-  volt
/+  default-agent, dbug, libvolt=volt
=,  volt
=,  client:volt
::
|%
+$  card  card:agent:gall
::
+$  versioned-state
  $%  state-0
  ==
::
+$  state-0
  $:  %0
      keys=(map ship pubkey)
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
  ~&  > '%volt agent initialized successfully'
  `this
::
++  on-save
  ^-  vase
  !>(state)
::
++  on-load
  |=  old-state=vase
  ^-  (quip card _this)
  ~&  > '%volt agent recompiled successfully'
  `this(state !<(versioned-state old-state))
::
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  =^  cards  state
  ?+    mark  (on-poke:def mark vase)
      %volt-client-command
    ?>  =(our.bowl src.bowl)
    (handle-command:hc !<(command vase))
  ::
      %volt-client-action
    ?<  =(our.bowl src.bowl)
    (handle-action:hc !<(action vase))
  ==
  [cards this]
::
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  `this
::
++  on-watch
  |=  =path
  ^-  (quip card _this)
  `this
::
++  on-agent
  |=  [=wire =sign:agent:gall]
  ^-  (quip card _this)
  ?+    -.sign  (on-agent:def wire sign)
      %kick
    ?~  prov  `this
    ?:  ?&  ?=(%set-provider -.wire)
            =(host.u.prov src.bowl)
        ==
      :_  this
      ~[(sub-provider prov)]
    `this
  ::
      %fact
    =^  cards  state
      ?+    p.cage.sign  `state
          %volt-provider-status
        `state
      ::
          %volt-provider-update
        `state
      ==
    [cards this]
  ::
      %watch-ack
    ?:  ?=(%set-provider -.wire)
      ?~  p.sign
        `this
      =/  =tank  leaf+"subscribe to provider {dap.bowl} failed"
      %-  (slog tank u.p.sign)
      `this(prov ~)
    `this
  ==
::
++  on-peek   on-peek:def
++  on-leave  on-leave:def
++  on-fail   on-fail:def
--
::
|_  =bowl:gall
++  handle-action
  |=  =action
  |^  ^-  (quip card _state)
  ?-    -.action
      %settle-htlc
    =^  cards  state
    :-  %+  fall
        %+  bind  (~(get by htlc.action) pres)
          |=  =preimage
          [(settle-htlc htlc.action preimage)]
        [(fail-htlc htlc.action)]
    state(pres (~(rem by htlc.action) pres))
   [cards state]
  ::
  ==
  ++  settle-htlc
    |=  [=htlc:provider =preimage]
    ^-  card
    %-  poke-provider  [%settle-htlc htlc preimage]
  ::
  ++  fail-htlc
    |=  =htlc:provider
    ^-  card
    %-  poke-provider  [%fail-htlc htlc]
  --
::
++  handle-command
  |=  =command
  ^-  (quip card _state)
  ?-    -.command
      %set-provider
    =/  sub-card=card  (sub-provider provider.command)
    :_  state(prov [~ provider.command])
    ?~  prov  ~[sub-card]
    :~  :*  %pass  /set-provider/[(scot %p host.u.prov)]
            %agent  [host.u.prov %volt-provider]  %leave  ~
        ==
        sub-card
    ==
  ::
  ==
::
++  sub-provider
  |=  provider=ship
  ^-  card
  :*  %pass  /set-provider/[(scot %p provider)]
      %agent  [provider %volt-provider]  %watch  /clients
  ==
::
++  poke-provider
  |=  act=action:provider:volt
  ^-  card
  ?~  prov  ~|("provider not set" !!)
  :*  %pass  /[(scot %da now.bowl)]
      %agent  [our.bowl %volt-provider]
      %poke  %volt-provider-action  !>([action])
  ==
--
