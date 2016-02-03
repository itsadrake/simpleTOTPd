module simpletotp.totp;

import simpletotp.hotp;
import std.string;
import std.datetime;

enum T0 = 0;
enum TI = 30;

int totp(
		const ubyte[] K,
		const ulong time,
		const int offset = 0,
		const int digits = TOK_LEN)
{
	ulong TC = (time - T0) / TI + offset;
	return hotp(K, TC, digits);
}

int totp(
		const string K,
		const ulong time,
		const int offset = 0,
		const int digits = TOK_LEN)
{
	return totp(K.representation, time, offset, digits);
}

bool verify_token(const ubyte[] K, const int token, const int sync)
{
	long now = Clock.currTime(UTC()).toUnixTime!long;
	if (totp(K, now) == token)
		return true;
	
	for (int i = 1; i <= sync; ++i)
		if (totp(K, now, -i) == token || totp(K, now, i) == token)
			return true;
	return false;
}

bool verify_token(const string K, const int token, const int sync)
{
	return verify_token(K.representation, token, sync);
}

unittest
{
	const string key = "12345678901234567890";
	assert(totp(key,          59, 0, 8) == 94287082);
	assert(totp(key,  1111111109, 0, 8) ==  7081804);
	assert(totp(key,  1111111111, 0, 8) == 14050471);
	assert(totp(key,  1234567890, 0, 8) == 89005924);
	assert(totp(key,  2000000000, 0, 8) == 69279037);
	assert(totp(key, 20000000000, 0, 8) == 65353130);
}
