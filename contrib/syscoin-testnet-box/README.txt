This is a private, difficulty 1 testnet in a box for litecoin - based off freewil's testnet-box for bitcoin (github.com/freewil/bitcoin-testnet-box).

Use it as follows:

  $ make start

This will start two nodes. You need two because otherwise the node won't
generate blocks. You now have a private testnet:

  litecoind -datadir=1  getinfo
  {
      "version" : 60300,
      "protocolversion" : 60001,
      "walletversion" : 60000,
      "balance" : 0.00000000,
      "blocks" : 0,
      "connections" : 1,
      "proxy" : "",
      "difficulty" : 0.00024414,
      "testnet" : true,
      "keypoololdest" : 1367704943,
      "keypoolsize" : 101,
      "paytxfee" : 0.00000000,
      "mininput" : 0.00010000,
      "errors" : ""
  }

  litecoind -datadir=2  getinfo
  {
      "version" : 60300,
      "protocolversion" : 60001,
      "walletversion" : 60000,
      "balance" : 0.00000000,
      "blocks" : 0,
      "connections" : 1,
      "proxy" : "",
      "difficulty" : 0.00024414,
      "testnet" : true,
      "keypoololdest" : 1367704943,
      "keypoolsize" : 101,
      "paytxfee" : 0.00000000,
      "mininput" : 0.00010000,
      "errors" : ""
  }


To start generating blocks:

  $ make generate-true
  
To stop generating blocks:

  $ make generate-false

OR, point your mining software at the address of the test machine, on either ports 19334 (Server 1) or 19344 (Server 2) using the username 'testnet' and the password 'testnet'. With a 7970, you should find a new block every second or so.

Using the command (if you are running the testnet on the same box as the miner - otherwise change 127.0.0.1 to the address of the testnet)

./cgminer --scrypt -o http://127.0.0.1:19334 -O testnet:testnet --shaders 2048 --thread-concurrency 8192 -w 256 -g2 -I 13 --auto-gpu --temp-overheat 81 --gpu-vddc 1.030 --temp-cutoff 97 --gpu-fan=100 --gpu-engine 700-1000 --gpu-memclock 1500

you should see this:

 cgminer version 3.1.0 - Started: [2013-05-05 08:08:34]
--------------------------------------------------------------------------------
 (5s):651.3K (avg):677.5Kh/s | A:12  R:2  HW:0  U:28.1/m  WU:522.7/m
 ST: 4  SS: 0  NB: 15  LW: 0  GF: 0  RF: 0
 Connected to 127.0.0.1 diff 16 without LP as user testnet
 Block: a9e247f0ce19261a...  Diff:16  Started: [08:09:03]  Best share: 514
--------------------------------------------------------------------------------
 [P]ool management [G]PU management [S]ettings [D]isplay options [Q]uit
 GPU 0:  62.0C 3472RPM | 611.2K/792.4Kh/s | A:15 R:2 HW:0 U: 35.16/m I:13
--------------------------------------------------------------------------------

 [2013-05-05 08:08:40] Accepted 0d79ae19 Diff 18/16 BLOCK! GPU 0
 [2013-05-05 08:08:40] New block detected on network
 [2013-05-05 08:08:41] Found block for pool 0!
 [2013-05-05 08:08:41] Accepted 02d01e0c Diff 91/16 BLOCK! GPU 0
 [2013-05-05 08:08:41] Found block for pool 0!
 [2013-05-05 08:08:42] Rejected 04ebc3f4 Diff 52/16 BLOCK! GPU 0
 [2013-05-05 08:08:42] New block detected on network
 [2013-05-05 08:08:44] Found block for pool 0!
 [2013-05-05 08:08:44] Accepted 0f0c8dfe Diff 17/16 BLOCK! GPU 0
 [2013-05-05 08:08:45] New block detected on network
 [2013-05-05 08:08:47] Found block for pool 0!
 [2013-05-05 08:08:47] Accepted 0ceb555f Diff 19/16 BLOCK! GPU 0
 [2013-05-05 08:08:48] New block detected on network
 [2013-05-05 08:08:48] Found block for pool 0!
 [2013-05-05 08:08:48] Accepted 0a46fc4a Diff 24/16 BLOCK! GPU 0
 [2013-05-05 08:08:48] New block detected on network
 [2013-05-05 08:08:56] Found block for pool 0!
 [2013-05-05 08:08:56] Accepted 02303381 Diff 116/16 BLOCK! GPU 0
 [2013-05-05 08:08:57] New block detected on network
 [2013-05-05 08:08:58] Found block for pool 0!
 [2013-05-05 08:08:58] Accepted 057fa852 Diff 46/16 BLOCK! GPU 0
 [2013-05-05 08:08:58] New block detected on network
 [2013-05-05 08:09:01] Found block for pool 0!
 [2013-05-05 08:09:01] Accepted 0f094309 Diff 17/16 BLOCK! GPU 0
 [2013-05-05 08:09:02] New block detected on network
 [2013-05-05 08:09:02] Found block for pool 0!
 [2013-05-05 08:09:02] Accepted 0da16004 Diff 18/16 BLOCK! GPU 0
 [2013-05-05 08:09:03] New block detected on network
  
To stop the two nodes:
  
  $ make stop
  
To clean up any files created while running the testnet 
(and restore to the original state)

  $ make clean

Like all testnet nodes, it is listening on port 19333.
The secondary node is listening on port 19343.

When running & generating coin - remember that you'll need the coins to mature before you can use them in a transaction.
