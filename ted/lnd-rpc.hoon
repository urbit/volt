::  ted/lnd-rpc.hoon
/-  spider, sur=volt
/+  *strandio, volt
=,  strand=strand:spider
=,  sur
^-  thread:spider
|=  v=vase
=+  !<([~ [=host-info:provider =action:rpc]] v)
=/  m  (strand ,vase)
;<  =response:rpc  bind:m  (~(send rpc:volt host-info) action)
(pure:m !>(response))
