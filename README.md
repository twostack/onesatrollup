# Description 

## A note about transaction sizes and composition

### Base Case Transaction 

### Normal Case Transaction

# Running the service

## Build it
The `-w` flag is to indicate stripping the debug symbols. Smaller binary is the result. 
```shell
$ go build -ldflags "-w" . 
```

## Run it
You should have a binary called `onesatrollup` in the home folder. This is a statically-linked 
binary for your platform, and needs no external library dependencies. 

The first time you run the application it will generate the Prover and Verifier keys for both 
the "base case" *and* the "normal case". So four keys in total. This will take a total of 
around 2 minutes. 
The next time you run the app the existing keys will be re-imported, but the startup time
does not appreciably reduce, so expect it to still take around 2 minutes for the app to boot. 
```shell
$ ./onesatrollup
```

## Generate a Base Case Proof
Base case proofs are for the issuance transactions. They are the start
of the chain of proofs.

The initial base case proof only needs the raw transaction data in Hex. 

```shell
$ curl --location 'http://localhost:8080/prove/base' \
--header 'Content-Type: application/json' \
--data '{
    "raw_tx": "020000000190bc0a14e94cdd565265d79c4f9bed0f6404241f3fb69d6458b30b41611317f7000000004847304402204e643ff6ed0e3c3e1e83f3e2c74a9d0613849bb624c1d12351f1152cf91ebc1f02205deaa38e3f8f8e43d1979f999c03ffa65b9087c1a6545ecffa2b7898c042bcb241feffffff0200ca9a3b000000001976a914662db6c1a68cdf035bfb9c6580550eb3520caa9d88ac40276bee000000001976a9142dbbeab87bd7a8fca8b2761e5d798dfd76d5af4988ac6f000000"
}'
```