# SSS32 #
![Image of two Volvelles used for secret recovery](./images/volvelles.jpg)

My concept for creating secret shares using paper computers (slide charts).
It is a design for splitting a secret encoded in the Bech32 alphabet into 2-of-n shares (where n <= 31) using pencil, paper and lookup tables.
There are numerous issues and more that need to be addressed before one could even think about using it for actual valuable data.
Right now I'm mostly interested to find out if paper sharing is really feasible.

A secret of 26 random Bech32 characters provides 130 bits of entropy, and a secret of 51 random Bech32 characters provides 255 bits of entropy.
However, to enable robust recovery, the secret data ought to contain an error correcting code.
Because each character of the secret is independently split into shares, any single character error in one of the shares translates into a single character error in the recovered secret which can be corrected by the error correcting code.
See the exercise at the end of "[Verifying Bech32 Checksums with Pen and Paper](http://r6.ca/blog/20180106T164028Z.html)" on how to attach the Bech32 error correcting code to a raw secret string by hand.
However, protecting the secret data is so important that one would want to design a checksum BCH code longer than 6 characters to get strong error correcting capabilities.

I still don't know if this proposed method all a good idea or not.
I've only experimented with encoding and recovering a 10 character "secret" data.
Generating 2-of-n shares is quite easy as all the shares are a function of the secret share and the first random share.
It only takes lookup up a pair of coordinates in a table to generate one character for each of the n shares together.
Recovering the secret data is more work; however, if your plan is to recover a hardware wallet anyways, it is reasonable for the hardware wallet to do the recovery from the shares itself for you.
Generating the error correcting code by hand is a bit more worrying, because it doesn't do you much good if your generate an incorrect checksum.
However, by doing 1 or 2 manual passes to verify the checksum is maybe adequate.
Also passing the secret data into the hardware wallet you wish to use, along with its checksum, would let the hardware wallet tell you if there was an error in the checksum.
I think creating more general 3-of-n schemes can be implemented too, but require work similar to recovery to generate rather than the simple lookup table process.
Generating 4-of-n and higher schemes may also be possible, but would require even more hand computation (i.e. computing lagrange polynomials.)

Maybe this scheme is workable for the subset of people that this would appeal to.
In anycase, my document is open source and available for those who want to tinker with it.
