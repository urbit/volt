::  ted/lnd.hoon
/-  spider, sur=volt
/+  *strandio, volt
=,  strand=strand:spider
=,  sur
^-  thread:spider
|=  v=vase
=+  !<([~ [=config:provider =action:rpc]] v)
=/  m  (strand ,vase)
;<  =response:rpc  bind:m  (~(send rpc:volt config) action)
%-
?-    -.response
    %&
  =/  res=result:rpc  +.response
  ?-    -.res
      %get-info
    (slog leaf+"Version: {(trip version.res)}" ~)
  ::
      %open-channel
    (slog leaf+"Funding txid: {(trip (en:base64:mimes:html funding-txid.res))}  Index: {(trip (scot %ud output-index.res))}" ~)
  ::
      %close-channel
    (slog leaf+"Closed!" ~)
  ::
      %send-payment
    (slog leaf+"Sent!" ~)
  ==
::
    %|
  =/  err=error:rpc  +.response
  (slog leaf+"Error: {(trip message.err)}" ~)
==
(pure:m !>(~))
