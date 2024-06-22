# tinypsk

tinypsk is lightweight and freestanding implementation of TLS v1.2 built to support only TLS_PSK_WITH_NULL_SHA. This means that tinypsk supports only pre-shared key communication without encryption and uses SHA256 as a primitive for Message Authentication Codes.

With tinypsk, one can create a secure communication channel between two parties, assuring these two properties:

- Authenticity
- Integrity

tinypsk is built for low-end embedded device and makes no use of dynamic memory. All the required memory is statically allocated in the library. Two custom allocators are used to handle that memory:

- Linear allocator
- Circular buffer allocator (it's not a standard name but one I came up with during the development phase)

## Using tinypsk

tinypsk assumes, as all TLS implementations do, that the underlying channel provides:

- In order communication
- Reliable communication (no loss of data)

Using tinypsk in your communication means that you have to provide the tinypsk init function with a transport layer structure, a send and a receive function. See the example for other informations.

If your transport layer provides the above-defined properies, you are good to go!

## Extending tinypsk

To my current understanding of my skills, I wrote tinypsk to be sufficiently modular to allow expansions with other cipher suites. Extending with other cipher suites, virtually, would require:

- Defining the cipher suite 2-byte identification in `tp_defines.h`
- Writing the cipher/decipher and cipher/decipher length functions in `record.c`
- Extending the checks in the record layer functions to check for the new cipher suite in `record.c` (this could be improved with some indirection, but tinypsk is born to be simple 😊)

## Build

Run `make build` to build with libc support or `make build_no_os` build a freestanding version.\
`make debug` and `make debug_no_os` build the library in debug mode.

## Testing

My intention is to test this library against a standard TLS implementation but for now this is not scheduled in my tasks.

## Example

Run `make example` to build a client and a server that communicate over TCP & tinypsk exchanging an echo message.