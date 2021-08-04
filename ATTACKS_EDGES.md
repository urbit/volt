# Lightning Attacks and Edge Cases

## volt Top-Level Recommendations
Based on the below.
* inside-Urbit HTLCs should use anchor outputs (low commitment tx fee attack)
* provider volt nodes should monitor the mempool (settlement blocking attack).
* non-provider nodes should not relay txs, since they don't have the resources to monitor the mempool

## HTLC Attacks

### low commitment tx fee
* A pays B pays C; B attacked
* Affected: routing nodes
* Mechanical: B can't post commitment tx with C fast enough to force preimage from C and get that preimage back to B
* Solution: Child Pays for Parent+anchor outputs
Summary:
  - intuition: when A posts a commitment tx, that starts a clock ticking for B to acquire and post preimage 
  - A posts reclaim HTLC tx, and now B's clock is ticking to post his own and force C to post preimage
  - B tries to post his own reclaim. But its fee is too low, and it doesn't clear before A's, and then C posts preimage.

### settlement blocking
* https://bitcoinops.org/en/newsletters/2020/04/29/#new-attack-against-ln-payment-atomicity
* https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-April/002639.html
* A pays B pays C; B attacked
* Affected: routing nodes
* Mechanial: commitment tx is confirmed, and then accepter can block settlement w low fee preimage post PLUS use of extra input to block B from seeing preimage
* Solutions
  - require mempool monitoring. Conclusion is not too serious if HTLCs are small enough to not be worth the effort of partitioning/bribing miners.
    * This stops pinning w preimage, since we see preimage
    * **problem 1** lots more CPU/mem for node to monitor mempool. This works well in Urbit/Volt, however, since low-resource nodes are edges.
    * **problem 2** C can partition the network by spending a "dummy" input in both a preimage settlement and dummy tx. Dummy tx goes to relays, real preimage spend goes to known miners.
  - anchor outputs on HTLCs. This fixes problem, but increases the cost of HTLC enforcement a lot, to the point where it might not be worth it.
Summary: 
- C broadcasts commitment tx and it confirms
- C broadcasts preimage settlement to some miners with a low fee. Also includes some "dummy" input in this. Partitions network another tx with that same "dummy" input to relay nodes.
- TODO: how does that dummy input block A from posting HTLC settlement?
- A reclaims offered HTLC after timelock
- C's preimage settlement goes through at some point
