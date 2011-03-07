/**
 * This file is part of Nokia InternetGatewayDevice v2 reference implementation
 * Copyright © 2010 Nokia Corporation and/or its subsidiary(-ies).
 * Contact: mika.saaranen@nokia.com
 * Developer(s): opensource@tieto.com
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

#include <gcrypt.h>
#include <pthread.h>
#include <errno.h>

// thread safety issue for libgrypt
GCRY_THREAD_OPTION_PTHREAD_IMPL;

/*
 * Initialize crypt library. Return 0 on success, otherwise -1
 */
int initialize_gcrypt()
{
    if ( !gcry_control( GCRYCTL_INITIALIZATION_FINISHED_P ) )
    {
        /* Version check should be the very first call because it
          makes sure that important subsystems are intialized. */
        if ( !gcry_check_version( GCRYPT_VERSION ) )
        {
            return -1;
        }

        /* Make libgrypt (gnutls) thread save. This assumes that we are using pthred for threading.
           Check http://www.gnu.org/software/gnutls/manual/gnutls.html#Multi_002dthreaded-applications */
        gcry_control( GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread );

        /* to disallow usage of the blocking /dev/random  */
        gcry_control( GCRYCTL_ENABLE_QUICK_RANDOM, 0 );

        /* Disable secure memory.  */
        gcry_control( GCRYCTL_DISABLE_SECMEM, 0 );

        /* Tell Libgcrypt that initialization has completed. */
        gcry_control( GCRYCTL_INITIALIZATION_FINISHED, 0 );
    }

    return 0;
}

/**
 * Hash data with SHA-256
 *
 * @param data Data which is hashed
 * @param data_len Length of data
 * @param hash Pointer to hashed data. Return value.
 * @return Length of hash or error code
 */
int crypt_calculate_sha256( const unsigned char *data, size_t data_len, unsigned char *hash )
{
    unsigned char *tmp_hash;
    int hash_len = 0;
    gcry_md_hd_t ctx;

    gcry_md_open( &ctx, GCRY_MD_SHA256, 0 );
    gcry_md_write( ctx, ( void * )data, data_len );
    gcry_md_final( ctx );

    tmp_hash = gcry_md_read( ctx, GCRY_MD_SHA256 );
    hash_len = gcry_md_get_algo_dlen( GCRY_MD_SHA256 );
    memcpy(( void * )hash, ( void * )tmp_hash, hash_len );

    gcry_md_close( ctx );

    if ( tmp_hash == NULL )
        return -1;

    return hash_len;
}

/**
 * Creates very random data for long term usage.
 *
 * @param bytes How many bytes of random data is created
 * @return Pointer to created data ot NULL
 */
void *crypt_create_random_value( size_t bytes )
{
    int ret;

    // check if gcrypt is initialized
    ret = initialize_gcrypt();

    if ( ret != 0 )
    {
        return NULL;
    }

    return gcry_random_bytes( bytes, GCRY_VERY_STRONG_RANDOM );
}

/**
 * pbkdf2-function is modified from libgcypt patch found from here:
 * http://lists.gnupg.org/pipermail/gcrypt-devel/2002-December/000202.html
 *
 * Not sure what happened for the patch, but it isn't found from libgcrypt.
 * Following license is from that patch:
 *
 * pkcs5.c Partial Password-Based Cryptography (PKCS#5) implementation
 * Copyright (C) 2002 Free Software Foundation, Inc.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
/**
 * Derives key with PKDF2 (http://tools.ietf.org/html/rfc2898#section-5.2)
 *
 * @param P      Password
 * @param Plen   Lentgth of password
 * @param S      Salt
 * @param Slen   Length of salt
 * @param c      Iteration count
 * @param dkLen  Intended length in octets of the derived key
 * @param DK     Derived key, a dkLen-octet string
 * @return 0 on success, otherwise fail
 */
int crypt_pbkdf2( const char *P, size_t Plen, const unsigned char *S,
                 size_t Slen, unsigned int c, unsigned int dkLen, unsigned char *DK )
{
    /*
    * 5.2 PBKDF2
    *
    *  PBKDF2 applies a pseudorandom function (see Appendix B.1 for an
    *  example) to derive keys. The length of the derived key is essentially
    *  unbounded. (However, the maximum effective search space for the
    *  derived key may be limited by the structure of the underlying
    *  pseudorandom function. See Appendix B.1 for further discussion.)
    *  PBKDF2 is recommended for new applications.
    *
    *  PBKDF2 (P, S, c, dkLen)
    *
    *  Options:        PRF        underlying pseudorandom function (hLen
    *                             denotes the length in octets of the
    *                             pseudorandom function output)
    *
    *  Input:          P          password, an octet string
    *                  S          salt, an octet string
    *                  c          iteration count, a positive integer
    *                  dkLen      intended length in octets of the derived
    *                             key, a positive integer, at most
    *                             (2^32 - 1) * hLen
    *
    *  Output:         DK         derived key, a dkLen-octet string
    */

    int PRF = GCRY_MD_SHA256;
    gcry_md_hd_t prf;
    unsigned char *U;
    unsigned int u;
    unsigned int hLen;
    unsigned int l;
    unsigned int r;
    int rc;
    unsigned char *p;
    int i;
    int k;

    hLen = gcry_md_get_algo_dlen( PRF );
    if (hLen == 0)
        return GPG_ERR_NOT_SUPPORTED;

    if (c == 0)
        return GPG_ERR_INV_ARG;

    if (dkLen == 0)
        return GPG_ERR_INV_ARG;

    /*
     *
     *  Steps:
     *
     *     1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
     *        stop.
     */

    if ( dkLen > 4294967295U )
        return GPG_ERR_INV_ARG;

    /*
     *     2. Let l be the number of hLen-octet blocks in the derived key,
     *        rounding up, and let r be the number of octets in the last
     *        block:
     *
     *                  l = CEIL (dkLen / hLen) ,
     *                  r = dkLen - (l - 1) * hLen .
     *
     *        Here, CEIL (x) is the "ceiling" function, i.e. the smallest
     *        integer greater than, or equal to, x.
     */

    l = dkLen / hLen;

    if ( dkLen % hLen )
        l++;

    r = dkLen - ( l - 1 ) * hLen;

    /*
     *     3. For each block of the derived key apply the function F defined
     *        below to the password P, the salt S, the iteration count c, and
     *        the block index to compute the block:
     *
     *                  T_1 = F (P, S, c, 1) ,
     *                  T_2 = F (P, S, c, 2) ,
     *                  ...
     *                  T_l = F (P, S, c, l) ,
     *
     *        where the function F is defined as the exclusive-or sum of the
     *        first c iterates of the underlying pseudorandom function PRF
     *        applied to the password P and the concatenation of the salt S
     *        and the block index i:
     *
     *                  F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
     *
     *        where
     *
     *                  U_1 = PRF (P, S || INT (i)) ,
     *                  U_2 = PRF (P, U_1) ,
     *                  ...
     *                  U_c = PRF (P, U_{c-1}) .
     *
     *        Here, INT (i) is a four-octet encoding of the integer i, most
     *        significant octet first.
     *
     *     4. Concatenate the blocks and extract the first dkLen octets to
     *        produce a derived key DK:
     *
     *                  DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
     *
     *     5. Output the derived key DK.
     *
     *  Note. The construction of the function F follows a "belt-and-
     *  suspenders" approach. The iterates U_i are computed recursively to
     *  remove a degree of parallelism from an opponent; they are exclusive-
     *  ored together to reduce concerns about the recursion degenerating
     *  into a small set of values.
     *
     */

    gcry_md_open( &prf, PRF, GCRY_MD_FLAG_HMAC );

    if ( prf == NULL )
        return GPG_ERR_INTERNAL;

    U = gcry_malloc( hLen );

    if ( !U )
    {
        rc = GPG_ERR_INTERNAL;
        goto done;
    }

    for ( i = 1; i <= l; i++ )
    {
        memset( DK + ( i - 1 ) * hLen, 0, i == l ? r : hLen );

        for ( u = 1; u <= c; u++ )
        {
            gcry_md_reset( prf );

            rc = gcry_md_setkey( prf, P, Plen );

            if ( rc != GPG_ERR_NO_ERROR )
            {
                goto done;
            }

            if ( u == 1 )
            {
                char tmp[4];
                gcry_md_write( prf, S, Slen );
                tmp[0] = ( i & 0xff000000 ) >> 24;
                tmp[1] = ( i & 0x00ff0000 ) >> 16;
                tmp[2] = ( i & 0x0000ff00 ) >> 8;
                tmp[3] = ( i & 0x000000ff ) >> 0;
                gcry_md_write( prf, tmp, 4 );
            }
            else
                gcry_md_write( prf, U, hLen );

            p = gcry_md_read( prf, PRF );

            if ( p == NULL )
            {
                rc = GPG_ERR_INTERNAL;
                goto done;
            }

            memcpy( U, p, hLen );

            for ( k = 0; k < ( i == l ? r : hLen ); k++ )
                DK[( i - 1 ) * hLen + k] ^= U[k];
        }
    }

    rc = GPG_ERR_NO_ERROR;

done:
    gcry_md_close( prf );
    gcry_free( U );
    return rc;
}

/**
 * Creates buffer with length of bytes filled with unpredictable data.
 * User needs to free returned pointer.
 *
 * @param bytes How many bytes of random data is created
 * @return Pointer to created data ot NULL
 */
void *crypt_create_nonce( size_t bytes )
{
    int ret = 0;

    // check if gcrypt is initialized
    ret = initialize_gcrypt();
    if ( ret != 0 )
    {
        return NULL;
    }

    unsigned char *rand = ( unsigned char * )malloc( bytes );
    if ( rand == NULL )
    {
        return NULL;
    }
    
    gcry_create_nonce( rand, bytes );

    return rand;
}
