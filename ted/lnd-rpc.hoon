::  ted/lnd-rpc.hoon
/-  spider, sur=volt
/+  *strandio, volt
=,  strand=strand:spider
=,  sur
^-  thread:spider
|=  v=vase
=+  !<([~ [=config:provider =action:rpc]] v)
=/  m  (strand ,vase)
;<  =response:rpc  bind:m  (~(send rpc:volt config) action)
(pure:m !>(response))
