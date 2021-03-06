package mandioca.bitcoin.rpc.response;

import java.util.Arrays;

@SuppressWarnings("unused")
public class GetRawTransactionVerboseResponse extends BitcoindRpcResponse {
    private boolean inActiveChain;
    private String hex;  // serialized, hex-encoded data for 'txid'  (data in GetRawTransactionResponse)
    private String txid;
    private String hash;
    private long size;
    private long vsize;
    private long weight;
    private int version;
    private long locktime;
    private Object[] vin;   // TODO (array of json objects)
    private Object[] vout;  // TODO (array of json objects)
    private String blockhash;
    private long confirmations;
    private long blocktime;
    private long time;

    public GetRawTransactionVerboseResponse() {
    }

    public boolean isInActiveChain() {
        return inActiveChain;
    }

    public String getHex() {
        return hex;
    }

    public String getTxid() {
        return txid;
    }

    public String getHash() {
        return hash;
    }

    public long getSize() {
        return size;
    }

    public long getVsize() {
        return vsize;
    }

    public long getWeight() {
        return weight;
    }

    public int getVersion() {
        return version;
    }

    public long getLocktime() {
        return locktime;
    }

    public Object[] getVin() {
        return vin;
    }

    public Object[] getVout() {
        return vout;
    }

    public String getBlockhash() {
        return blockhash;
    }

    public long getConfirmations() {
        return confirmations;
    }

    public long getBlocktime() {
        return blocktime;
    }

    public long getTime() {
        return time;
    }

    @Override
    public String toString() {
        return "GetRawTransactionVerboseResponse{" +
                "  inActiveChain=" + inActiveChain + "\n" +
                ", hex='" + hex + '\'' + "\n" +
                ", txid='" + txid + '\'' + "\n" +
                ", hash='" + hash + '\'' + "\n" +
                ", size=" + size + "\n" +
                ", vsize=" + vsize + "\n" +
                ", weight=" + weight + "\n" +
                ", version=" + version + "\n" +
                ", locktime=" + locktime + "\n" +
                ", vin=" + Arrays.toString(vin) + "\n" +
                ", vout=" + Arrays.toString(vout) + "\n" +
                ", blockhash='" + blockhash + '\'' + "\n" +
                ", confirmations=" + confirmations + "\n" +
                ", blocktime=" + blocktime + "\n" +
                ", time=" + time + "\n" +
                ", rpcErrorResponse=" + super.rpcErrorResponse + "\n" +
                '}';
    }
}

/*
$ ./bitcoin-cli help getrawtransaction
getrawtransaction "txid" ( verbose "blockhash" )

Return the raw transaction data.

By default this function only works for mempool transactions. When called with a blockhash
argument, getrawtransaction will return the transaction if the specified block is available and
the transaction is found in that block. When called without a blockhash argument, getrawtransaction
will return the transaction if it is in the mempool, or if -txindex is enabled and the transaction
is in a block in the blockchain.

Hint: Use gettransaction for wallet transactions.

If verbose is 'true', returns an Object with information about 'txid'.
If verbose is 'false' or omitted, returns a string that is serialized, hex-encoded data for 'txid'.

Arguments:
1. txid         (string, required) The transaction id
2. verbose      (boolean, optional, default=false) If false, return a string, otherwise return a json object
3. blockhash    (string, optional) The block in which to look for the transaction

Result (if verbose is not set or set to false):
"data"      (string) The serialized, hex-encoded data for 'txid'

Result (if verbose is set to true):
{
  "in_active_chain": b, (bool) Whether specified block is in the active chain or not (only present with explicit "blockhash" argument)
  "hex" : "data",       (string) The serialized, hex-encoded data for 'txid'
  "txid" : "id",        (string) The transaction id (same as provided)
  "hash" : "id",        (string) The transaction hash (differs from txid for witness transactions)
  "size" : n,             (numeric) The serialized transaction size
  "vsize" : n,            (numeric) The virtual transaction size (differs from size for witness transactions)
  "weight" : n,           (numeric) The transaction's weight (between vsize*4-3 and vsize*4)
  "version" : n,          (numeric) The version
  "locktime" : ttt,       (numeric) The lock time
  "vin" : [               (array of json objects)
     {
       "txid": "id",    (string) The transaction id
       "vout": n,         (numeric)
       "scriptSig": {     (json object) The script
         "asm": "asm",  (string) asm
         "hex": "hex"   (string) hex
       },
       "sequence": n      (numeric) The script sequence number
       "txinwitness": ["hex", ...] (array of string) hex-encoded witness data (if any)
     }
     ,...
  ],
  "vout" : [              (array of json objects)
     {
       "value" : x.xxx,            (numeric) The value in BTC
       "n" : n,                    (numeric) index
       "scriptPubKey" : {          (json object)
         "asm" : "asm",          (string) the asm
         "hex" : "hex",          (string) the hex
         "reqSigs" : n,            (numeric) The required sigs
         "type" : "pubkeyhash",  (string) The type, eg 'pubkeyhash'
         "addresses" : [           (json array of string)
           "address"        (string) bitcoin address
           ,...
         ]
       }
     }
     ,...
  ],
  "blockhash" : "hash",   (string) the block hash
  "confirmations" : n,      (numeric) The confirmations
  "blocktime" : ttt         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)
  "time" : ttt,             (numeric) Same as "blocktime"
}

Examples:
> bitcoin-cli getrawtransaction "mytxid"
> bitcoin-cli getrawtransaction "mytxid" true
> curl --user myusername --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getrawtransaction", "params": ["mytxid", true] }' -H 'content-type: text/plain;' http://127.0.0.1:8332/
> bitcoin-cli getrawtransaction "mytxid" false "myblockhash"
> bitcoin-cli getrawtransaction "mytxid" true "myblockhash"
*/
