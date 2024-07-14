#!/usr/bin/env python3
# Copyright (c) 2015-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the ZMQ notification interface."""

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.test_framework import SyscoinTestFramework
from test_framework.messages import hash256, CNEVMBlock, CNEVMBlockConnect, CNEVMBlockDisconnect, uint256_from_str
from test_framework.util import (
    assert_equal,
)
from io import BytesIO
from time import sleep
from threading import Thread
import random

# these would be handlers for the 3 types of calls from Syscoin on Geth
def receive_thread_nevm(test_framework, idx, subscriber):
    while test_framework.running:
        try:
            test_framework.log.info('receive_thread_nevm waiting to receive... idx {}'.format(idx))
            data = subscriber.receive()
            if data[0] == b"nevmcomms":
                subscriber.send([b"nevmcomms", b"ack"])
            elif data[0] == b"nevmblock":
                hashStr = hash256(str(random.randint(-0x80000000, 0x7fffffff)).encode())
                hashTopic = uint256_from_str(hashStr)
                nevmBlock = CNEVMBlock(hashTopic, hashTopic, hashTopic, b"nevmblock")
                subscriber.send([b"nevmblock", nevmBlock.serialize()])
            elif data[0] == b"nevmconnect":
                evmBlockConnect = CNEVMBlockConnect()
                evmBlockConnect.deserialize(BytesIO(data[1]))
                resBlock = subscriber.addBlock(evmBlockConnect)
                res = b""
                if resBlock:
                    res = b"connected"
                else:
                    res = b"not connected"
                # stay paused during delay test
                while subscriber.artificialDelay and test_framework.running:
                    sleep(0.1)
                subscriber.send([b"nevmconnect", res])
            elif data[0] == b"nevmdisconnect":
                evmBlockDisconnect = CNEVMBlockDisconnect()
                evmBlockDisconnect.deserialize(BytesIO(data[1]))
                resBlock = subscriber.deleteBlock(evmBlockDisconnect)
                res = b""
                if resBlock:
                    res = b"disconnected"
                else:
                    res = b"not disconnected"
                subscriber.send([b"nevmdisconnect", res])
            else:
                test_framework.log.info("Unknown topic in REQ {}".format(data))
        except zmq.ContextTerminated:
            sleep(1)
            break
        except zmq.ZMQError:
            test_framework.log.warning('zmq error, socket closed unexpectedly.')
            sleep(1)
            break

def thread_generate(test_framework, node):
    test_framework.log.info('thread_generate start')
    test_framework.generatetoaddress(node, 1, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=test_framework.no_op)
    test_framework.log.info('thread_generate done')

# Test may be skipped and not have zmq installed
try:
    import zmq
except ImportError:
    pass

# this simulates the Geth node publisher, publishing back to Syscoin subscriber
class ZMQPublisher:
    def __init__(self, socket):
        self.socket = socket
        self.sysToNEVMBlockMapping = {}
        self.NEVMToSysBlockMapping = {}
        self.artificialDelay = False

    # Send message to subscriber
    def _send_to_publisher_and_check(self, msg_parts):
        self.socket.send_multipart(msg_parts)

    def receive(self):
        return self.socket.recv_multipart()

    def send(self, msg_parts):
        return self._send_to_publisher_and_check(msg_parts)

    def close(self):
        self.socket.close()

    def addBlock(self, evmBlockConnect):
        if evmBlockConnect.sysblockhash == 0:
            return True
        if self.sysToNEVMBlockMapping.get(evmBlockConnect.sysblockhash) is not None or self.NEVMToSysBlockMapping.get(evmBlockConnect.blockhash) is not None:
            return False
        self.sysToNEVMBlockMapping[evmBlockConnect.sysblockhash] = evmBlockConnect
        self.NEVMToSysBlockMapping[evmBlockConnect.blockhash] = evmBlockConnect.sysblockhash
        return True

    def deleteBlock(self, evmBlockDisconnect):
        nevmConnect = self.sysToNEVMBlockMapping.get(evmBlockDisconnect.sysblockhash)
        if nevmConnect is None:
            return False
        sysMappingHash = self.NEVMToSysBlockMapping.get(nevmConnect.blockhash)
        if sysMappingHash is None:
            return False
        if sysMappingHash is not nevmConnect.sysblockhash:
            return False

        self.sysToNEVMBlockMapping.pop(evmBlockDisconnect.sysblockhash, None)
        self.NEVMToSysBlockMapping.pop(nevmConnect.blockhash, None)
        return True

    def getLastSYSBlock(self):
        return list(self.NEVMToSysBlockMapping.values())[-1]

    def getLastNEVMBlock(self):
        return self.sysToNEVMBlockMapping[self.getLastSYSBlock()]

    def clearMappings(self):
        self.sysToNEVMBlockMapping = {}
        self.NEVMToSysBlockMapping = {}

class ZMQTest(SyscoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        if self.is_wallet_compiled():
            self.requires_wallet = True
        self.extra_args = [["-whitelist=noban@127.0.0.1"]] * self.num_nodes

    def skip_test_if_missing_module(self):
        self.skip_if_no_py3_zmq()
        self.skip_if_no_syscoind_zmq()

    def run_test(self):
        try:
            import zmq
        except ImportError:
            pass
        self.running = True
        self.ctx = zmq.Context()
        self.ctxpub = zmq.Context()
        self.threads = []
        try:
            self.test_basic()
        finally:
            self.running = False
            self.log.debug("Destroying ZMQ context")
            self.ctx.destroy(linger=None)
            self.ctxpub.destroy(linger=None)
            for t in self.threads:
                t.join()

    def setup_zmq_test(self, address, idx, *, recv_timeout=60, sync_blocks=True):
        socket = self.ctx.socket(zmq.REP)
        subscriber = ZMQPublisher(socket)
        self.extra_args[idx] = ["-zmqpubnevm=%s" % address]

        self.restart_node(idx, self.extra_args[idx])

        subscriber.socket.bind(address)
        subscriber.socket.setsockopt(zmq.RCVTIMEO, recv_timeout*1000)
        return subscriber

    def test_basic(self):
        address = 'tcp://127.0.0.1:29446'
        address1 = 'tcp://127.0.0.1:29447'

        self.log.info("setup subscribers...")
        nevmsub  = self.setup_zmq_test(address, 0)
        nevmsub1 = self.setup_zmq_test(address1, 1)
        self.connect_nodes(0, 1)
        self.sync_blocks()

        num_blocks = 10
        self.log.info("Generate %(n)d blocks (and %(n)d coinbase txes)" % {"n": num_blocks})
        # start the threads to handle pub/sub of SYS/GETH communications
        t1 = Thread(target=receive_thread_nevm, args=(self, 0, nevmsub,))
        t2 = Thread(target=receive_thread_nevm, args=(self, 1, nevmsub1,))
        t1.start()
        t2.start()
        self.threads.extend([t1, t2])

        self.generatetoaddress(self.nodes[0], num_blocks, ADDRESS_BCRT1_UNSPENDABLE)
        self.sync_blocks()
        # test simple disconnect, save best block go back to 205 (first NEVM block) and then reconsider back to tip
        bestblockhash = self.nodes[0].getbestblockhash()
        assert_equal(int(bestblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[1].getbestblockhash(), bestblockhash)
        # save 205 since when invalidating 206, the best block should be 205
        prevblockhash = self.nodes[0].getblockhash(205)
        blockhash = self.nodes[0].getblockhash(206)
        self.nodes[0].invalidateblock(blockhash)
        self.nodes[1].invalidateblock(blockhash)
        self.sync_blocks()
        # ensure block 205 is the latest on publisher
        assert_equal(int(prevblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        # go back to 210 (tip)
        self.nodes[0].reconsiderblock(blockhash)
        self.nodes[1].reconsiderblock(blockhash)
        self.sync_blocks()
        # check that publisher is on the tip (210) again
        assert_equal(int(bestblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[1].getbestblockhash(), bestblockhash)
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        # restart nodes and check for consistency
        self.log.info('restarting node 0')
        self.restart_node(0, self.extra_args[0])
        self.sync_blocks()
        assert_equal(int(bestblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[1].getbestblockhash(), bestblockhash)
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        self.log.info('restarting node 1')
        self.restart_node(1, self.extra_args[1])
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(int(bestblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[1].getbestblockhash(), bestblockhash)
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        # reindex nodes and there should be 6 connect messages from blocks 205-210
        self.log.info('reindexing node 0')
        self.extra_args[0] += ["-reindex"]
        nevmsub.clearMappings()
        self.restart_node(0, self.extra_args[0])
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(int(bestblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[1].getbestblockhash(), bestblockhash)
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        self.log.info('reindexing node 1')
        self.extra_args[1] += ["-reindex"]
        nevmsub1.clearMappings()
        self.restart_node(1, self.extra_args[1])
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(int(bestblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[1].getbestblockhash(), bestblockhash)
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        # reorg test
        self.disconnect_nodes(0, 1)
        self.log.info("Mine 4 blocks on Node 0")
        self.generatetoaddress(self.nodes[0], 4, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)
        assert_equal(self.nodes[1].getblockcount(), 210)
        assert_equal(self.nodes[0].getblockcount(), 214)
        besthash_n0 = self.nodes[0].getbestblockhash()

        self.log.info("Mine competing 6 blocks on Node 1")
        self.generatetoaddress(self.nodes[1], 6, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)
        assert_equal(self.nodes[1].getblockcount(), 216)

        self.log.info("Connect nodes to force a reorg")
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(self.nodes[0].getblockcount(), 216)
        badhash = self.nodes[1].getblockhash(212)

        self.log.info("Invalidate block 2 on node 0 and verify we reorg to node 0's original chain")
        self.nodes[0].invalidateblock(badhash)
        assert_equal(self.nodes[0].getblockcount(), 214)
        assert_equal(self.nodes[0].getbestblockhash(), besthash_n0)
        self.nodes[0].reconsiderblock(badhash)
        self.sync_blocks()
        self.log.info("Artificially delaying node0")
        nevmsub.artificialDelay = True
        self.log.info("Generating on node0 in separate thread")
        t3 = Thread(target=thread_generate, args=(self, self.nodes[0],))
        t3.start()
        self.threads.append(t3)
        self.log.info("Creating re-org and letting node1 become longest chain, node0 should re-org to node0")
        self.generatetoaddress(self.nodes[1], 10, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)
        besthash = self.nodes[1].getbestblockhash()
        nevmsub.artificialDelay = False
        sleep(1)
        self.sync_blocks()
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        assert_equal(int(besthash, 16), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())
        self.log.info('done')

if __name__ == '__main__':
    ZMQTest().main()
