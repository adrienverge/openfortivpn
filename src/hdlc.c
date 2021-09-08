/*
 *  Copyright (C) 2015 Adrien Vergé
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "hdlc.h"

/*
 * Encode and decode PPP packets from and into HDLC frames.
 *
 * RFC 1622 describes the use of HDLC-like framing for PPP encapsulated packets:
 * https://www.rfc-editor.org/info/rfc1662
 */

#define in_sending_accm(byte) \
	((byte) < 0x20 || ((byte) & 0x7f) == 0x7d || ((byte) & 0x7f) == 0x7e)

#define in_receiving_accm(byte) \
	((byte) < 0x20)

/*
 * Lookup table used to calculate the FCS, as generated in RFC 1662.
 */
static const uint16_t fcs_tab[] = {
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

/*
 * Calculates a new FCS from the current FCS and new data.
 *
 * @param[in] sum      Current FCS value.
 * @param[in] seq      Array of new data.
 * @param[in] length   Length of the array of new data.
 * @return             new FCS value.
 */
static uint16_t frame_checksum_16bit(uint16_t sum, const uint8_t *seq, size_t length)
{
	while (length--)
		sum = (sum >> 8) ^ fcs_tab[(sum ^ *seq++) & 0xff];

	return sum;
}

/*
 * Precalculated FCS for Address and Control fields.
 *
 *     address_control_checksum = frame_checksum_16bit(0xffff, { 0xff, 0x03 }, 2);
 */
static const uint16_t address_control_checksum = 0x3de3;


/*
 * Each frame begins with a Flag Sequence.
 * Only one Flag Sequence is required between two frames.
 * The first frame begins with a Flag Sequence.
 * Subsequent frames rely on the Flag Sequence that ends the previous frame.
 */
static int need_flag_sequence;

/*
 * Upon connection, the first frame begins with a Flag Sequence.
 */
void init_hdlc(void)
{
	need_flag_sequence = 1;
}


/*
 * Wraps a PPP packet into an HDLC frame and write it to a buffer.
 *
 * @param[out] frame    The buffer to store the encoded frame.
 * @param[in]  frmsize  The output buffer size.
 * @param[in]  packet   The buffer containing the packet.
 * @param[in]  pktsize  The input packet size.
 * @return              the number of bytes written to the buffer (i.e. the
 *                      HDLC-encoded frame length) or ERR_HDLC_BUFFER_TOO_SMALL
 *                      if the output buffer is too small
 */
ssize_t hdlc_encode(uint8_t *frame, size_t frmsize,
                    const uint8_t *packet, size_t pktsize)
{
	ssize_t written = 0;
	uint16_t checksum;
	const uint8_t address_control_fields[] = { 0xff, 0x03 };
	int i;
	uint8_t byte;

	if (frmsize < 7)
		return ERR_HDLC_BUFFER_TOO_SMALL;

	// In theory each frame begins with a Flag Sequence, but it is omitted
	// if the previous frame ends with a Flag Sequence.
	if (need_flag_sequence)
		frame[written++] = 0x7e;

	// Escape and write Frame Address and Control fields
	frame[written++] = address_control_fields[0];
	frame[written++] = 0x7d;
	frame[written++] = address_control_fields[1] ^ 0x20;

	checksum = address_control_checksum; // Precalculated for Address Control

	for (i = 0; i < pktsize; i++) {
		byte = packet[i];

		if (frmsize < written + 2)
			return ERR_HDLC_BUFFER_TOO_SMALL;
		if (in_sending_accm(byte)) {
			frame[written++] = 0x7d;
			frame[written++] = byte ^ 0x20;
		} else {
			frame[written++] = byte;
		}
	}

	if (frmsize < written + 3)
		return ERR_HDLC_BUFFER_TOO_SMALL;

	checksum = frame_checksum_16bit(checksum, packet, pktsize);

	// Escape and write Frame Check Sequence field
	checksum ^= 0xffff;
	byte = checksum & 0x00ff;
	if (in_sending_accm(byte)) {
		frame[written++] = 0x7d;
		frame[written++] = byte ^ 0x20;
	} else {
		frame[written++] = byte;
	}
	byte = (checksum >> 8) & 0x00ff;
	if (in_sending_accm(byte)) {
		frame[written++] = 0x7d;
		frame[written++] = byte ^ 0x20;
	} else {
		frame[written++] = byte;
	}

	// Each frame ends with a Flag Sequence
	frame[written++] = 0x7e;
	need_flag_sequence = 0;

	return written;
}

/*
 * Finds the first frame in a buffer, starting search at start.
 *
 * @param[in]     buffer   The input buffer.
 * @param[in]     bufsize  The input buffer size.
 * @param[in,out] start    Offset of the beginning of the first frame in the buffer.
 * @return                 the length of the first frame or ERR_HDLC_NO_FRAME_FOUND
 *                         if no frame is found.
 */
ssize_t hdlc_find_frame(const uint8_t *buffer, size_t bufsize, off_t *start)
{
	int i, s = -1, e = -1;

	// Look for frame start
	for (i = *start; i < bufsize - 2; i++) {
		if (buffer[i] == 0x7e) { // Flag Sequence
			s = i + 1;
			break;
		}
	}
	if (s == -1)
		return ERR_HDLC_NO_FRAME_FOUND;

	// Discard empty frames
	while (s < bufsize - 2 && buffer[s] == 0x7e) // consecutive Flag Sequences
		s++;

	// Look for frame end
	for (i = s; i < bufsize; i++) {
		if (buffer[i] == 0x7e) { // Flag Sequence
			e = i;
			break;
		}
	}
	if (e == -1)
		return ERR_HDLC_NO_FRAME_FOUND;

	*start = s;
	return e - s;
}

/*
 * Extracts the first PPP packet found in the input buffer.
 *
 * The frame should be passed without its surrounding Flag Sequence (0x7e) bytes.
 *
 * @param[in]  frame    The buffer containing the encoded frame.
 * @param[in]  frmsize  The input buffer size.
 * @param[out] packet   The buffer to store the decoded packet.
 * @param[in]  pktsize  The output packet buffer size.
 * @return              the number of bytes written to the output packet
 *                      buffer, or < 0 in case of error.
 */
ssize_t hdlc_decode(const uint8_t *frame, size_t frmsize,
                    uint8_t *packet, size_t pktsize)
{
	off_t start = 0;
	ssize_t written = 0;
	int has_address_control_fields = 0;
	int i;
	int in_escape;
	uint16_t checksum;

	if (frmsize < 5)
		return ERR_HDLC_INVALID_FRAME;

	// Remove Address and escaped Control fields
	if (frame[0] == 0xff && frame[1] == 0x7d && frame[2] == (0x03 ^ 0x20)) {
		start += 3;
		has_address_control_fields = 1;
	}

	in_escape = 0;
	for (i = start; i < frmsize; i++) {
		uint8_t byte = frame[i];

		if (byte == 0x7d) { // Control Escape
			if (in_escape)
				return ERR_HDLC_INVALID_FRAME;
			in_escape = 1;
			continue;
		} else if (in_escape) {
			byte ^= 0x20;
			in_escape = 0;
		} else if (in_receiving_accm(byte)) {
			continue; // Drop characters possibly introduced by DCE
		}
		if (written >= pktsize)
			return ERR_HDLC_BUFFER_TOO_SMALL;
		packet[written++] = byte;
	}
	if (in_escape)
		return ERR_HDLC_INVALID_FRAME;

	if (written < 3)
		return ERR_HDLC_INVALID_FRAME;

	// Control Frame Check Sequence field validity and remove it
	if (has_address_control_fields)
		checksum = address_control_checksum;
	else
		checksum = 0xffff;
	checksum = frame_checksum_16bit(checksum, packet, written);
	if (checksum != 0xf0b8)
		return ERR_HDLC_BAD_CHECKSUM;
	written -= 2;

	return written;
}
