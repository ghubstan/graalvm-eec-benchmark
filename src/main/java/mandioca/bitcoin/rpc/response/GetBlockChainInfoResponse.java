package mandioca.bitcoin.rpc.response;

import java.math.BigDecimal;
import java.util.Arrays;

@SuppressWarnings("unused")
public class GetBlockChainInfoResponse extends BitcoindRpcResponse {

    private String chain;
    private int blocks;
    private int headers;
    private String bestblockhash;
    private int difficulty;
    private long mediantime;
    private BigDecimal verificationprogress;
    private boolean initialblockdownload;
    private String chainwork;
    private long sizeOnDisk;
    private boolean pruned;
    private long pruneheight;
    private boolean automaticPruning;
    private long pruneTargetSize;
    @SuppressWarnings("MismatchedReadAndWriteOfArray")
    private Softfork[] softforks;
    private Bip9Softforks bip9Softforks;
    private String warnings;

    public GetBlockChainInfoResponse() {
    }

    public String getChain() {
        return chain;
    }

    public int getBlocks() {
        return blocks;
    }

    public int getHeaders() {
        return headers;
    }

    public String getBestblockhash() {
        return bestblockhash;
    }

    public int getDifficulty() {
        return difficulty;
    }

    public long getMediantime() {
        return mediantime;
    }

    public BigDecimal getVerificationprogress() {
        return verificationprogress;
    }

    public boolean isInitialblockdownload() {
        return initialblockdownload;
    }

    public String getChainwork() {
        return chainwork;
    }

    public long getSizeOnDisk() {
        return sizeOnDisk;
    }

    public boolean isPruned() {
        return pruned;
    }

    public long getPruneheight() {
        return pruneheight;
    }

    public boolean isAutomaticPruning() {
        return automaticPruning;
    }

    public long getPruneTargetSize() {
        return pruneTargetSize;
    }

    public String getWarnings() {
        return warnings;
    }

    @Override
    public String toString() {
        return "GetBlockChainInfoResponse{" + "\n" +
                "  chain='" + chain + '\'' + "\n" +
                ", blocks=" + blocks + "\n" +
                ", headers=" + headers + "\n" +
                ", bestblockhash='" + bestblockhash + '\'' + "\n" +
                ", getDifficulty=" + difficulty + "\n" +
                ", mediantime=" + mediantime + "\n" +
                ", verificationprogress=" + verificationprogress + "\n" +
                ", initialblockdownload=" + initialblockdownload + "\n" +
                ", chainwork='" + chainwork + '\'' + "\n" +
                ", sizeOnDisk=" + sizeOnDisk + "\n" +
                ", pruned=" + pruned + "\n" +
                ", pruneheight=" + pruneheight + "\n" +
                ", automaticPruning=" + automaticPruning + "\n" +
                ", pruneTargetSize=" + pruneTargetSize + "\n" +
                ", softforks=" + Arrays.toString(softforks) + "\n" +
                ", bip9Softforks=" + bip9Softforks + "\n" +
                ", warnings=" + warnings + "\n" +
                ", rpcErrorResponse=" + super.rpcErrorResponse + "\n" +
                '}';
    }

    static class Softfork {
        private String id;
        private int version;
        private Object reject;

        public Softfork() {
        }

        @Override
        public String toString() {
            return "Softfork{" +
                    "id='" + id + '\'' +
                    ", version=" + version +
                    ", reject='" + reject + '\'' +
                    '}';
        }
    }

    static class Bip9Softforks {
        private Object csv;
        private Object segwit;

        public Bip9Softforks() {
        }

        @Override
        public String toString() {
            return "Bip9Softfork{" +
                    "csv=" + csv +
                    ", segwit=" + segwit +
                    '}';
        }
    }
}

/*
$ ./bitcoin-cli help getblockchaininfo
getblockchaininfo
Returns an object containing various state info regarding blockchain processing.

Result:
{
  "chain": "xxxx",              (string) current network name as defined in BIP70 (main, test, regtest)
  "blocks": xxxxxx,             (numeric) the current number of blocks processed in the server
  "headers": xxxxxx,            (numeric) the current number of headers we have validated
  "bestblockhash": "...",       (string) the hash of the currently best block
  "getDifficulty": xxxxxx,         (numeric) the current getDifficulty
  "mediantime": xxxxxx,         (numeric) median time for the current best block
  "verificationprogress": xxxx, (numeric) estimate of verification progress [0..1]
  "initialblockdownload": xxxx, (bool) (debug information) estimate of whether this node is in Initial Block Download mode.
  "chainwork": "xxxx"           (string) total amount of work in active chain, in hexadecimal
  "size_on_disk": xxxxxx,       (numeric) the estimated size of the block and undo files on disk
  "pruned": xx,                 (boolean) if the blocks are subject to pruning
  "pruneheight": xxxxxx,        (numeric) lowest-height complete block stored (only present if pruning is enabled)
  "automatic_pruning": xx,      (boolean) whether automatic pruning is enabled (only present if pruning is enabled)
  "prune_target_size": xxxxxx,  (numeric) the getTarget size used by pruning (only present if automatic pruning is enabled)
  "softforks": [                (array) status of softforks in progress
     {
        "id": "xxxx",           (string) name of softfork
        "version": xx,          (numeric) block version
        "reject": {             (object) progress toward rejecting pre-softfork blocks
           "status": xx,        (boolean) true if threshold reached
        },
     }, ...
  ],
  "bip9_softforks": {           (object) status of BIP9 softforks in progress
     "xxxx" : {                 (string) name of the softfork
        "status": "xxxx",       (string) one of "defined", "started", "locked_in", "active", "failed"
        "bit": xx,              (numeric) the bit (0-28) in the block version field used to signal this softfork (only for "started" status)
        "startTime": xx,        (numeric) the minimum median time past of a block at which the bit gains its meaning
        "timeout": xx,          (numeric) the median time past of a block at which the deployment is considered failed if not yet locked in
        "since": xx,            (numeric) height of the first block to which the status applies
        "statistics": {         (object) numeric statistics about BIP9 signalling for a softfork (only for "started" status)
           "period": xx,        (numeric) the length in blocks of the BIP9 signalling period
           "threshold": xx,     (numeric) the number of blocks with the version bit set required to activate the feature
           "elapsed": xx,       (numeric) the number of blocks elapsed since the beginning of the current period
           "count": xx,         (numeric) the number of blocks with the version bit set in the current period
           "possible": xx       (boolean) returns false if there are not enough blocks left in this period to pass activation threshold
        }
     }
  }
  "warnings" : "...",           (string) any network and blockchain warnings.
}

Examples:
> bitcoin-cli getblockchaininfo
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getblockchaininfo", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:8332/
 */
