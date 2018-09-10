/*** use WOLFSSL to realize Algorithms sha256 and RSA2048 ***/

    /*** types used defined ***/
    //SHA256 with WOLFSSL API
    int sha256_test(void)
    {
        wc_Sha256 sha;
        byte      hash[WC_SHA256_DIGEST_SIZE];
        byte buffer[1024];  // fill buffer with data to hash

        testVector a, b;
        testVector test_sha[2];
        int ret;
        int times = sizeof(test_sha) / sizeof(struct testVector), i;

        a.input  = "fdsafdsaf";
        a.output = "\xBA\x78\x16\xBF\x8F\x01\xCF\xEA\x41\x41\x40\xDE\x5D\xAE\x22"
                   "\x23\xB0\x03\x61\xA3\x96\x17\x7A\x9C\xB4\x10\xFF\x61\xF2\x00"
                   "\x15\xAD";
        a.inLen  = XSTRLEN(a.input);
        a.outLen = XSTRLEN(a.output);

        b.input  = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        b.output = "\x24\x8D\x6A\x61\xD2\x06\x38\xB8\xE5\xC0\x26\x93\x0C\x3E\x60"
                   "\x39\xA3\x3C\xE4\x59\x64\xFF\x21\x67\xF6\xEC\xED\xD4\x19\xDB"
                   "\x06\xC1";
        b.inLen  = XSTRLEN(b.input);
        b.outLen = XSTRLEN(b.output);

        test_sha[0] = a;
        test_sha[1] = b;

        ret = wc_InitSha256(&sha);
        if (ret != 0)
            return ret;

        for (i = 0; i < times; ++i) {
            ret = wc_Sha256Update(&sha, (byte*)test_sha[i].input, (word32)test_sha[i].inLen); //can be called again and again
            if (ret != 0)
                return ret;

            ret = wc_Sha256Final(&sha, hash);
            if (ret != 0)
                return ret;

            if (XMEMCMP(hash, test_sha[i].output, WC_SHA256_DIGEST_SIZE) != 0)
                return -10 - i;
        }

        return 0;
    }
    puts(wc_Sha256Final);