/*
 * Copyright (C) 2012-2013 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */


#include "esp_packet.h"
#include "sha256hmac.h"
#include <library.h>
#include <utils/debug.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>
#include <bio/bio_reader.h>
#include <bio/bio_writer.h>
#include <string.h>
#include <stdio.h>
#define BUFFLEN 1500
#define EVP_MAX_MD_SIZE 64
#ifndef WIN32
#include <netinet/in.h>
#endif

typedef struct private_esp_packet_t private_esp_packet_t;

/**
 * Private additions to esp_packet_t.
 */
struct private_esp_packet_t {

	/**
	 * Public members
	 */
	esp_packet_t public;

	/**
	 * Raw ESP packet
	 */
	packet_t *packet;

	/**
	 * Payload of this packet
	 */
	ip_packet_t *payload;

	/**
	 * Next Header info (e.g. IPPROTO_IPIP)
	 */
	uint8_t next_header;

};

//hkdf
void compute_hmac_ex(unsigned char* dest, const uint8_t *key, uint32_t klen, const uint8_t *msg, uint32_t mlen)
	{
		uint8_t md[SHA256_DIGESTLEN] = {0};
		HMAC_SHA256_CTX hmac;
		hmac_sha256_init(&hmac, key, klen);
		hmac_sha256_update(&hmac, msg, mlen);
		hmac_sha256_final(&hmac, md);
		memcpy(dest, md, SHA256_DIGESTLEN);
	}
 

void HKDF(const unsigned char *salt, int salt_len,
          const unsigned char *ikm, int ikm_len,
          const unsigned char *info, int info_len,
          unsigned char *okm, int okm_len)
{
    unsigned char prk[EVP_MAX_MD_SIZE];
	compute_hmac_ex(prk, (const uint8_t *)salt, salt_len, (const uint8_t *)ikm, ikm_len);
    unsigned char prev[EVP_MAX_MD_SIZE];
    memset(prev, 0x00, EVP_MAX_MD_SIZE);

    int iter = (okm_len + 31) / 32;

    for (int i = 0; i < iter; i++) {
        unsigned char hmac_input[EVP_MAX_MD_SIZE];
        if (i == 0) {
            memcpy(hmac_input, info, info_len);
            hmac_input[info_len] = 0x01;
        } else {
            memcpy(hmac_input, prev, 32);
            memcpy(hmac_input + 32, info, info_len);
            hmac_input[32 + info_len] = i + 1;
        }

        unsigned char hmac_out[EVP_MAX_MD_SIZE];
		compute_hmac_ex(hmac_out, (const uint8_t *)prk, 32, (const uint8_t *)hmac_input, info_len + 32 * (i == 0 ? 0 : 1)+1);

        memcpy(prev, hmac_out, 32);
        memcpy(okm + i * 32, hmac_out,
               (i == iter - 1) ? okm_len - i * 32 : 32);
    }
}

/**
	 *派生量子密钥
	 *
	 * 通过spi和原始密钥派生
	 * 
	 * 
	 *
	 * @param key			原始密钥
	 * @param next_seqno	序列号
	 * @param keysize		密钥长度
	 * @return				TRUE if 获取成功
*/

static void derive_key(unsigned char* key, int next_seqno,int keysize) {
	unsigned char salt[32] = {0};
    unsigned char info[32];
    unsigned char okm[keysize];
	sprintf(info, "%d", next_seqno);
	HKDF(salt, sizeof(salt), key, strlen(key), info, strlen(info), okm, sizeof(okm));
    memcpy(key,okm,keysize);
}

/**
	 *获取量子密钥
	 *
	 * 通过spi和序列号获取对应的密钥
	 * 
	 * 
	 *
	 * @param spi			spi
	 * @param next_seqno	序列号
	 * @param key_type		TRUE表示加密，FALSE表示解密
	 * @param qk			量子密钥存储
	 * @param keysize		密钥长度
	 * @return				TRUE if 获取成功
	 */

static bool getqsk(uint32_t spi, uint32_t next_seqno, bool key_type,chunk_t *qk,size_t keysize) {
	int range = 0;
	static uint32_t eleft = 0, eright = 0; //加密窗口
	static uint32_t dleft = 0, dright = 0; //解密窗口
	static u_char tmp_ekey[256]; //加密密钥
	static u_char tmp_dkey[256]; //解密密钥
	u_char key[keysize+1];
	int ret = 0, cr, fd;
	struct sockaddr_in serv_addr, cli_addr;
	socklen_t client_addr_size;
	char buf[BUFFLEN], rbuf[BUFFLEN];
	
	fd = socket(AF_INET, SOCK_STREAM, 0);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(50000);
	inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr.s_addr);
	if (key_type) {
		if (next_seqno == 1 || next_seqno > eright) { // 向km请求密钥和密钥派生参数
			cr = connect(fd, &serv_addr, sizeof(serv_addr)); //连接对方服务器
			if (cr < 0) {
				perror("getqk connect error!\n");
				return false;
			}
			sprintf(buf, "getsk %u %d %u 0\n", spi, keysize, next_seqno);
			ret = send(fd, buf, strlen(buf), 0);
			if (ret < 0) {
				perror("getqsk send error!\n");
				return false;
			}
			ret = read(fd, rbuf, sizeof(rbuf));
			if (ret < 0) {
				perror("getqsk read error!\n");
				return false;
			}
			sscanf(rbuf, "%[^ ] %d", tmp_ekey, &range);
			eleft = eright;
			eright += range;
		}
		memcpy(key, tmp_ekey, keysize);
	}
	else {
		if (next_seqno == 1 || next_seqno > dright) { // 向km请求密钥和密钥派生参数
			cr = connect(fd, &serv_addr, sizeof(serv_addr)); //连接对方服务器
			if (cr < 0) {
				perror("getqk connect error!\n");
				return false;
			}
			sprintf(buf, "getsk %u %d %u 1\n", spi, keysize, next_seqno);
			ret = send(fd, buf, strlen(buf), 0);
			if (ret < 0) {
				perror("getqsk send error!\n");
				return false;
			}
			ret = read(fd, rbuf, sizeof(rbuf));
			if (ret < 0) {
				perror("getqsk read error!\n");
				return false;
			}
			sscanf(rbuf, "%[^ ] %d", tmp_dkey, &range);
			dleft = dright;
			dright += range;
		}
		memcpy(key, tmp_dkey, keysize);
	}
	derive_key(key, next_seqno,keysize);
	
	*qk = chunk_alloc(keysize);
	memcpy(qk->ptr, key, keysize);
	close(fd);
	return true;
}


int establish_connection_e() {
	static int socket_fd = -1; // 静态变量用于保存套接字的文件描述符
    if (socket_fd == -1) {
        // 第一次调用，创建套接字
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd == -1) {
            perror("Failed to create socket");
            // 处理套接字创建失败的情况
			return -1;
        }
        // 可以在这里进行套接字的初始化配置
		struct sockaddr_in serv_addr;
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(50000);	// 设置服务器端口号
		inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr.s_addr);// 设置服务器IP地址
		int connect_result = connect(socket_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
		if (connect_result == -1) {
			perror("getqotpk connect error!\n");
			return -1;
    	}
		}
    return socket_fd;
}

int establish_connection_d() {
	static int socket_fd = -1; // 静态变量用于保存套接字的文件描述符
    if (socket_fd == -1) {
        // 第一次调用，创建套接字
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd == -1) {
            perror("Failed to create socket");
            // 处理套接字创建失败的情况
			return -1;
        }
        // 可以在这里进行套接字的初始化配置
		struct sockaddr_in serv_addr;
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(50000);	// 设置服务器端口号
		inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr.s_addr);// 设置服务器IP地址
		int connect_result = connect(socket_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
		if (connect_result == -1) {
			perror("getqotpk connect error!\n");
			return -1;
    	}
		}
    return socket_fd;
}


/**
	 *获取量子OTP密钥
	 *
	 * 通过spi和序列号获取对应的密钥
	 * 
	 * 
	 *
	 * @param spi			spi
	 * @param next_seqno	序列号
	 * @param key_type		TRUE表示加密，FALSE表示解密
	 * @param qk			量子密钥存储
	 * @param keysize		密钥长度
	 * @return				TRUE if 获取成功
	 */

	/*
static bool getqotpk(uint32_t spi, uint32_t next_seqno, bool key_type,chunk_t *qk,size_t keysize) {
	static u_char tmp_ekey[1025]; //加密密钥
	static u_char tmp_dkey[1025]; //解密密钥
	u_char key[keysize+1];
	int ret = 0,M_size;
	for(int i=0;i<keysize;i++)
	key[i]=1;
	// char buf[BUFFLEN], rbuf[BUFFLEN];
	// int fd;
	// if (key_type){
	// 	sprintf(buf, "getotpk %u %u 0\n", spi, next_seqno);
	// 	fd=establish_connection_e();
	// 	 if (fd == -1) {
    //     // 处理建立连接失败的情况
    //     perror("establish_connection error!\n");
	// 	return false;
    // 	}
	// }
	// else{
	// 	sprintf(buf, "getotpk %u %u 1\n", spi, next_seqno);
	// 	fd=establish_connection_d();
	// 	 if (fd == -1) {
    //     // 处理建立连接失败的情况
    //     perror("establish_connection error!\n");
	// 	return false;
    // 	}
	// }
	// ret = send(fd, buf, strlen(buf), 0);
	// if (ret < 0) {
	// 	perror("getqotpk send error!\n");
	// 	return false;
	// }
	// ret = read(fd, rbuf, sizeof(rbuf));
	// if (ret < 0) {
	// 	perror("getqotpk read error!\n");
	// 	return false;
	// }
	// if (key_type){
	// 	sscanf(rbuf, "%[^ ] %d", tmp_ekey, &M_size);
	// 	memcpy(key, tmp_ekey, keysize);
	// }
	// else{
	// 	sscanf(rbuf, "%[^ ] %d", tmp_dkey, &M_size);
	// 	memcpy(key, tmp_dkey, keysize);
	// }

	//derive_key(key, next_seqno,keysize);

    *qk = chunk_alloc(keysize);
	memcpy(qk->ptr, key, keysize);
	
	return true;
}
*/

/**
 * Forward declaration for clone()
 */
static private_esp_packet_t *esp_packet_create_internal(packet_t *packet);

METHOD(packet_t, set_source, void,
	private_esp_packet_t *this, host_t *src)
{
	return this->packet->set_source(this->packet, src);
}

METHOD2(esp_packet_t, packet_t, get_source, host_t*,
	private_esp_packet_t *this)
{
	return this->packet->get_source(this->packet);
}

METHOD(packet_t, set_destination, void,
	private_esp_packet_t *this, host_t *dst)
{
	return this->packet->set_destination(this->packet, dst);
}

METHOD2(esp_packet_t, packet_t, get_destination, host_t*,
	private_esp_packet_t *this)
{
	return this->packet->get_destination(this->packet);
}

METHOD(packet_t, get_data, chunk_t,
	private_esp_packet_t *this)
{
	return this->packet->get_data(this->packet);
}

METHOD(packet_t, set_data, void,
	private_esp_packet_t *this, chunk_t data)
{
	return this->packet->set_data(this->packet, data);
}

METHOD(packet_t, get_dscp, uint8_t,
	private_esp_packet_t *this)
{
	return this->packet->get_dscp(this->packet);
}

METHOD(packet_t, set_dscp, void,
	private_esp_packet_t *this, uint8_t value)
{
	this->packet->set_dscp(this->packet, value);
}

METHOD(packet_t, get_metadata, metadata_t*,
	private_esp_packet_t *this, const char *key)
{
	return this->packet->get_metadata(this->packet, key);
}

METHOD(packet_t, set_metadata, void,
	private_esp_packet_t *this, const char *key, metadata_t *data)
{
	this->packet->set_metadata(this->packet, key, data);
}

METHOD(packet_t, skip_bytes, void,
	private_esp_packet_t *this, size_t bytes)
{
	return this->packet->skip_bytes(this->packet, bytes);
}

METHOD(packet_t, clone_, packet_t*,
	private_esp_packet_t *this)
{
	private_esp_packet_t *pkt;

	pkt = esp_packet_create_internal(this->packet->clone(this->packet));
	pkt->payload = this->payload ? this->payload->clone(this->payload) : NULL;
	pkt->next_header = this->next_header;
	return &pkt->public.packet;
}

METHOD(esp_packet_t, parse_header, bool,
	private_esp_packet_t *this, uint32_t *spi)
{
	bio_reader_t *reader;
	uint32_t seq;

	reader = bio_reader_create(this->packet->get_data(this->packet));
	if (!reader->read_uint32(reader, spi) ||
		!reader->read_uint32(reader, &seq))
	{
		DBG1(DBG_ESP, "failed to parse ESP header: invalid length");
		reader->destroy(reader);
		return FALSE;
	}
	reader->destroy(reader);

	DBG2(DBG_ESP, "parsed ESP header with SPI %.8x [seq %u]", *spi, seq);
	*spi = htonl(*spi);
	return TRUE;
}

/**
 * Check padding as specified in RFC 4303
 */
static bool check_padding(chunk_t padding)
{
	size_t i;

	for (i = 0; i < padding.len; ++i)
	{
		if (padding.ptr[i] != (uint8_t)(i + 1))
		{
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Remove the padding from the payload and set the next header info
 */
static bool remove_padding(private_esp_packet_t *this, chunk_t plaintext)
{
	uint8_t next_header, pad_length;
	chunk_t padding, payload;
	bio_reader_t *reader;

	reader = bio_reader_create(plaintext);
	if (!reader->read_uint8_end(reader, &next_header) ||
		!reader->read_uint8_end(reader, &pad_length))
	{
		DBG1(DBG_ESP, "parsing ESP payload failed: invalid length");
		goto failed;
	}
	if (!reader->read_data_end(reader, pad_length, &padding) ||
		!check_padding(padding))
	{
		DBG1(DBG_ESP, "parsing ESP payload failed: invalid padding");
		goto failed;
	}
	this->payload = ip_packet_create(reader->peek(reader));
	reader->destroy(reader);
	if (!this->payload)
	{
		DBG1(DBG_ESP, "parsing ESP payload failed: unsupported payload");
		return FALSE;
	}
	this->next_header = next_header;
	payload = this->payload->get_encoding(this->payload);

	DBG3(DBG_ESP, "ESP payload:\n  payload %B\n  padding %B\n  "
		 "padding length = %hhu, next header = %hhu", &payload, &padding,
		 pad_length, this->next_header);
	return TRUE;

failed:
	reader->destroy(reader);
	chunk_free(&plaintext);
	return FALSE;
}

METHOD(esp_packet_t, decrypt, status_t,
	private_esp_packet_t *this, esp_context_t *esp_context)
{
	bio_reader_t *reader;
	uint32_t spi, seq;
	chunk_t data, iv, icv, aad, ciphertext, plaintext,qk;
	aead_t *aead;

	DESTROY_IF(this->payload);
	this->payload = NULL;

	data = this->packet->get_data(this->packet);
	aead = esp_context->get_aead(esp_context);
	
	reader = bio_reader_create(data);
	if (!reader->read_uint32(reader, &spi) ||
		!reader->read_uint32(reader, &seq) ||
		!reader->read_data(reader, aead->get_iv_size(aead), &iv) ||
		!reader->read_data_end(reader, aead->get_icv_size(aead), &icv) ||
		reader->remaining(reader) % aead->get_block_size(aead))
	{
		DBG1(DBG_ESP, "ESP decryption failed: invalid length");
		return PARSE_ERROR;
	}
	ciphertext = reader->peek(reader);
	reader->destroy(reader);
	if (!getqsk(spi, seq, FALSE, &qk,  aead->get_key_size(aead))) {
		DBG1(DBG_ESP, "get qsk failed!");
			return FAILED;
	}
	else {
		if (!aead->set_key(aead, qk)) {
			DBG1(DBG_ESP, "set quantum key failed!");
				return FAILED;
		}
	}
	if (!esp_context->verify_seqno(esp_context, seq))
	{
		DBG1(DBG_ESP, "ESP sequence number verification failed:\n  "
			 "src %H, dst %H, SPI %.8x [seq %u]",
			 get_source(this), get_destination(this), spi, seq);
		return VERIFY_ERROR;
	}
	DBG3(DBG_ESP, "ESP decryption:\n  SPI %.8x [seq %u]\n  IV %B\n  "
		 "encrypted %B\n  ICV %B", spi, seq, &iv, &ciphertext, &icv);

	/* include ICV in ciphertext for decryption/verification */
	ciphertext.len += icv.len;
	/* aad = spi + seq */
	aad = chunk_create(data.ptr, 8);

	if (!aead->decrypt(aead, ciphertext, aad, iv, &plaintext))
	{
		DBG1(DBG_ESP, "ESP decryption or ICV verification failed");
		return FAILED;
	}
	esp_context->set_authenticated_seqno(esp_context, seq);

	if (!remove_padding(this, plaintext))
	{
		return PARSE_ERROR;
	}
	chunk_clear(&qk);
	return SUCCESS;
}

/**
 * Generate the padding as specified in RFC4303
 */
static void generate_padding(chunk_t padding)
{
	size_t i;

	for (i = 0; i < padding.len; ++i)
	{
		padding.ptr[i] = (uint8_t)(i + 1);
	}
}

METHOD(esp_packet_t, encrypt, status_t,
	private_esp_packet_t *this, esp_context_t *esp_context, uint32_t spi)
{
	chunk_t iv, icv, aad, padding, payload, ciphertext,qk;
	bio_writer_t *writer;
	uint32_t next_seqno;
	size_t blocksize, plainlen;
	aead_t *aead;
	iv_gen_t *iv_gen;

	this->packet->set_data(this->packet, chunk_empty);

	if (!esp_context->next_seqno(esp_context, &next_seqno))
	{
		DBG1(DBG_ESP, "ESP encapsulation failed: sequence numbers cycled");
		return FAILED;
	}

	aead = esp_context->get_aead(esp_context);
	if (!getqsk(spi,next_seqno,TRUE,&qk, aead->get_key_size(aead))) {
		DBG1(DBG_ESP, "get qsk failed!");
		return FAILED;
	}
	else {
		if (!aead->set_key(aead,qk)) {
			DBG1(DBG_ESP, "set quantum key failed!");
			return FAILED;
		}
	}
	iv_gen = aead->get_iv_gen(aead);
	if (!iv_gen)
	{
		DBG1(DBG_ESP, "ESP encryption failed: no IV generator");
		return NOT_FOUND;
	}

	blocksize = aead->get_block_size(aead);
	iv.len = aead->get_iv_size(aead);
	icv.len = aead->get_icv_size(aead);

	/* plaintext = payload, padding, pad_length, next_header */
	payload = this->payload ? this->payload->get_encoding(this->payload)
							: chunk_empty;
	plainlen = payload.len + 2;
	padding.len = pad_len(plainlen, blocksize);
	/* ICV must be on a 4-byte boundary */
	padding.len += pad_len(iv.len + plainlen + padding.len, 4);
	plainlen += padding.len;

	/* len = spi, seq, IV, plaintext, ICV */
	writer = bio_writer_create(2 * sizeof(uint32_t) + iv.len + plainlen +
							   icv.len);
	writer->write_uint32(writer, ntohl(spi));
	writer->write_uint32(writer, next_seqno);

	iv = writer->skip(writer, iv.len);
	if (!iv_gen->get_iv(iv_gen, next_seqno, iv.len, iv.ptr))
	{
		DBG1(DBG_ESP, "ESP encryption failed: could not generate IV");
		writer->destroy(writer);
		return FAILED;
	}

	/* plain-/ciphertext will start here */
	ciphertext = writer->get_buf(writer);
	ciphertext.ptr += ciphertext.len;
	ciphertext.len = plainlen;

	writer->write_data(writer, payload);

	padding = writer->skip(writer, padding.len);
	generate_padding(padding);

	writer->write_uint8(writer, padding.len);
	writer->write_uint8(writer, this->next_header);

	/* aad = spi + seq */
	aad = writer->get_buf(writer);
	aad.len = 8;
	icv = writer->skip(writer, icv.len);

	DBG3(DBG_ESP, "ESP before encryption:\n  payload = %B\n  padding = %B\n  "
		 "padding length = %hhu, next header = %hhu", &payload, &padding,
		 (uint8_t)padding.len, this->next_header);

	/* encrypt/authenticate the content inline */
	if (!aead->encrypt(aead, ciphertext, aad, iv, NULL))
	{
		DBG1(DBG_ESP, "ESP encryption or ICV generation failed");
		writer->destroy(writer);
		return FAILED;
	}

	DBG3(DBG_ESP, "ESP packet:\n  SPI %.8x [seq %u]\n  IV %B\n  "
		 "encrypted %B\n  ICV %B", ntohl(spi), next_seqno, &iv,
		 &ciphertext, &icv);

	this->packet->set_data(this->packet, writer->extract_buf(writer));
	writer->destroy(writer);
	chunk_clear(&qk);
	return SUCCESS;
}

METHOD(esp_packet_t, get_next_header, uint8_t,
	private_esp_packet_t *this)
{
	return this->next_header;
}

METHOD(esp_packet_t, get_payload, ip_packet_t*,
	private_esp_packet_t *this)
{
	return this->payload;
}

METHOD(esp_packet_t, extract_payload, ip_packet_t*,
	private_esp_packet_t *this)
{
	ip_packet_t *payload;

	payload = this->payload;
	this->payload = NULL;
	return payload;
}

METHOD2(esp_packet_t, packet_t, destroy, void,
	private_esp_packet_t *this)
{
	DESTROY_IF(this->payload);
	this->packet->destroy(this->packet);
	free(this);
}

static private_esp_packet_t *esp_packet_create_internal(packet_t *packet)
{
	private_esp_packet_t *this;

	INIT(this,
		.public = {
			.packet = {
				.set_source = _set_source,
				.get_source = _get_source,
				.set_destination = _set_destination,
				.get_destination = _get_destination,
				.get_data = _get_data,
				.set_data = _set_data,
				.get_dscp = _get_dscp,
				.set_dscp = _set_dscp,
				.get_metadata = _get_metadata,
				.set_metadata = _set_metadata,
				.skip_bytes = _skip_bytes,
				.clone = _clone_,
				.destroy = _destroy,
			},
			.get_source = _get_source,
			.get_destination = _get_destination,
			.get_next_header = _get_next_header,
			.parse_header = _parse_header,
			.decrypt = _decrypt,
			.encrypt = _encrypt,
			.get_payload = _get_payload,
			.extract_payload = _extract_payload,
			.destroy = _destroy,
		},
		.packet = packet,
		.next_header = IPPROTO_NONE,
	);
	return this;
}

/**
 * Described in header.
 */
esp_packet_t *esp_packet_create_from_packet(packet_t *packet)
{
	private_esp_packet_t *this;

	this = esp_packet_create_internal(packet);

	return &this->public;
}

/**
 * Described in header.
 */
esp_packet_t *esp_packet_create_from_payload(host_t *src, host_t *dst,
											 ip_packet_t *payload)
{
	private_esp_packet_t *this;
	packet_t *packet;

	packet = packet_create_from_data(src, dst, chunk_empty);
	this = esp_packet_create_internal(packet);
	this->payload = payload;
	if (payload)
	{
		this->next_header = payload->get_version(payload) == 4 ? IPPROTO_IPIP
															   : IPPROTO_IPV6;
	}
	else
	{
		this->next_header = IPPROTO_NONE;
	}
	return &this->public;
}
