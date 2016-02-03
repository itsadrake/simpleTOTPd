# simpleTOTPd

A minimal implementation of the [TOTP](https://tools.ietf.org/html/rfc6238) and [HOTP](https://tools.ietf.org/html/rfc4226) algorithms (based on [simpleTOTP](https://github.com/Thanix/simpleTOTP)).

## Dependencies

- A D compiler (tested with DMD64 v2.070.0)
- DUB

## Building

Run `dub` to compile `libsimpleTOTPd.a`, and `dub test` run a simple test suite.
Intended to be used as a DUB dependency.

## Licence

MIT, see `LICENCE` file for full text.
