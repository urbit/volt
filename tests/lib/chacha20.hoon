/+  *test, cc=chacha20
|%
+$  vector  :*  key=hexb
                nonce=hexb
                counter=hexb
                rounds-20-res=(list @ux)
            ==
++  vectors
  ^-  (list vector)
  :~  :*  key
          nonce
          counter
          rounds-20-res
      ==
  ==
::
++  test-all-vectors
  ^-  tang
  |^  ;:  weld
          %+  category  "quarter-round"
          (zing (turn vectors check-quarter-round))
          %+  category  "chacha20"
          (zing (turn vectors check-chacha))
      ==
  ::
  ++  check-quarter-round
    |=  v=vector
  ++  check-chacha
    |=  v=vector
--
