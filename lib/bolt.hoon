::  bolt.hoon
::  Library functions to implement Lightning BOLT RFCs.
::
/-  *bolt
/+  bc=bitcoin
|%
::  +bolt-tx
::    helpers for building & signing commitment/HTLC txs
::
++  bolt-tx
  |%
  ++  obscured-commitment-number
    |=  [cn=commitment-number]
        ::  generate obscured commitment number. Uses:
    ::    - commitment number (e.g. 42)
    ::    - SHA256(payment_basepoint from open_channel || payment_basepoint from accept_channel)
    ::      e.g. (034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa || 032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991)
    ::      = last 6 bytes (48 bits) in big endian: 0x2bb038521914
    ::    - 0x2bb038521914 XOR 42
  ++  funding-input
    |=  o=outpoint
    ::  generate input from funding-outpoint
    ::    sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits of the obscured commitment number
  ++  remote-output
  ++  local-output
  ++  anchor-output
    ::  <local_funding_pubkey/remote_funding_pubkey> OP_CHECKSIG OP_IFDUP
    ::  OP_NOTIF
    ::  OP_16 OP_CHECKSEQUENCEVERIFY
    ::  OP_ENDIF
  ++  htlc-output
    |=  =htlc
    ::  if from=us, do received, else offered
    |^
    ++  offered
    ++  received
    --
  ++  commitment-tx
    |=  [c=chan our=?]
    ::  returns txid and full tx and signature?
    ::  Algo:
    ::  generate HTLC outputs
    ::  nVersion: 02000000
    ::  nLocktime: upper 8 bits are 0x20, lower 24 bits are the lower 24 bits of the obscured commitment number
  --
--
