module simpletotp;

import std.digest.sha, std.digest.hmac;
import std.datetime;
import std.string;

enum TOK_LEN = 6;
enum T0 = 0;
enum TI = 30;

int hotp(const ubyte[] K, ulong C, const int digits = TOK_LEN)
{
	ubyte[8] counter;
	for (int i = 8; i --> 0;)
	{
		counter[i] = C & 0xFF;
		C >>= 8;
	}
	auto hmac = HMAC!SHA1(K);
	hmac.put(counter);
	ubyte[20] hash = hmac.finish();

	int offset = hash[19] & 0x0F;

	uint value = 0;
	for (int i = 0; i < 4; ++i)
	{
		value <<= 8;
		value |= hash[offset + i];
	}
	value &= 0x7F_FF_FF_FF;

	static const int[10] pow10 = [
		1, 10, 100, 1000, 10000, 100000,
		1000000, 10000000, 100000000, 1000000000
	];

	return value % pow10[digits];
}

int totp(
		const ubyte[] K,
		const ulong time,
		const int offset = 0,
		const int digits = TOK_LEN)
{
	ulong TC = (time - T0) / TI + offset;
	return hotp(K, TC, digits);
}

bool verify_token(const ubyte[] K, const int token, const int sync)
{
	long now = Clock.currTime(UTC()).toUnixTime!long;
	if (totp(K, now) == token)
		return true;
	
	for (int i = 1; i <= sync; ++i)
		if (totp(K, now, -sync) == token ||
		    totp(K, now, sync) == token)
			return true;
	return false;
}

int hotp(const string K, ulong C, const int digits = TOK_LEN)
{
	return hotp(K.representation, C, digits);
}

int totp(
		const string K,
		const ulong time,
		const int offset = 0,
		const int digits = TOK_LEN)
{
	return totp(K.representation, time, offset, digits);
}

bool verify_token(const string K, const int token, const int sync)
{
	return verify_token(K.representation, token, sync);
}

unittest
{
	import std.string;

	const string key = "12345678901234567890";
	assert(totp(key,          59, 0, 8) == 94287082);
	assert(totp(key,  1111111109, 0, 8) ==  7081804);
	assert(totp(key,  1111111111, 0, 8) == 14050471);
	assert(totp(key,  1234567890, 0, 8) == 89005924);
	assert(totp(key,  2000000000, 0, 8) == 69279037);
	assert(totp(key, 20000000000, 0, 8) == 65353130);
}
