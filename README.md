# simpleTOTPd

A minimal implementation of the [TOTP](https://tools.ietf.org/html/rfc6238) and [HOTP](https://tools.ietf.org/html/rfc4226) algorithms (based on [simpleTOTP](https://github.com/Thanix/simpleTOTP)).

## Dependencies

- A D compiler (tested with DMD64 v2.070.0)
- DUB

## Building

Run `dub` to compile `libsimpleTOTPd.a`, and `dub test` run a simple test suite.
Intended to be used as a DUB dependency.

## Using

The modules `simpletotp.totp` and `simpletotp.hotp` are available for your importing pleasure.
The functions you can use are the following:

```
int totp(const ubyte[] key, const ulong time, const int offset = 0, const int digits = 6);
```
Calculates the TOTP token for `key` at given `time` plus `offset` times interval (30s), truncated to `digits` digits.

```
int hotp(const ubyte[] key, const ulong counter, const int digits = 6);
```
Calculates the HOTP token for `key` with given `counter`, truncated to `digits` digits.

```
bool verify_token(const ubyte[] key, const int token, const int sync);
```
Returns `true` if the TOTP token for `key` at current time (± sync times interval) matches `token`, `false` otherwise.

## Licence

MIT, see `LICENCE` file for full text.
