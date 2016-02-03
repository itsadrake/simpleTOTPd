module simpletotp.hotp;

import std.string;
import std.digest.sha;
import std.digest.hmac;

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

int hotp(const string K, ulong C, const int digits = TOK_LEN)
{
	return hotp(K.representation, C, digits);
}


