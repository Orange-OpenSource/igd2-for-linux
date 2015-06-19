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
 
#ifndef _CRYPT_H_
#define _CRYPT_H_

int crypt_calculate_sha256( const unsigned char *data, size_t data_len, unsigned char *hash );

void *crypt_create_random_value( size_t bytes );
int crypt_pbkdf2( const char *P, size_t Plen, const unsigned char *S,
                  size_t Slen, unsigned int c, unsigned int dkLen, unsigned char *DK );
void *crypt_create_nonce( size_t bytes );

#endif //_CRYPT_H_
