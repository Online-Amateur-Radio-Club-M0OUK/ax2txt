/*
 * Program:	AX2TXT
 * Purpose:	Decode ax25 frames from stdin to stdout.
 * Created: Sat 20th Jan 2024, by Paula G8PZT
 * Notes:	- Very quick and dirty, could be improved!
 * 			- Created with tab indenting, Tabsize=3.
 * Version:	1.2, 21/1/2024
 * Modified:
 * 20/1/24	1.1	Corrected AckRqst / AckRply display.
 * 21/1/24	1.2	Added NetRom L3/4 and Nodes bcast decoding
 *
 */

#include <stdio.h>
#include <ctype.h>


typedef	unsigned char byte;
typedef	int	bool;

#define	MAX_FRAME	1000

// SSID bits
#define	EXTENSION	0x01	// AX25 "address extension" bit
#define	DAMA			0x20	// Source ssid only.  0 = dama master
#define	EAX25			0x40	// Source ssid only.  0 = Modulo-127
#define	REPEATED		0x80	// AX25 "has been repeated" bit
#define	CMDRSP		0x80	/* Command/response bit*/

// Comand/response bits
#define 	RESPONSE		1
#define	COMMAND		2
//#define	POLLFINAL	4	/* P/F bit is set */

// Control field defines
#define	I				0x00
#define	S				0x01
#define	RR				0x01
#define	RNR			0x05
#define	REJ			0x09
#define	U				0x03
#define	SABM			0x2f
#define	SABME			0x6f
#define	DISC			0x43
#define	DM				0x0f
#define	UA				0x63
#define	FRMR			0x87
#define	UI				0x03
#define	PF				0x10	// Poll/final bit
#define	EPF			0x100	// Poll/final bit in modulo-128 I and S frames */


/* AX25 L3 Protocol ID fields */

/* These first two seem to be obsolete and are usually both set to 1 */
#define PID_FIRST		0x80	/* First fragment of frame */
#define PID_LAST		0x40	/* Last fragment of frame */
#define PID_NO_L3		0x30	/* No layer 3, just data */
#define PID_MASK		0x3F	/* Mask for remaining bits */

#define PID_TEXNET	0x03	/* TEXNET datagram protocol */
#define	PID_LQ		0x04	/* Link quality protocol */
#define	PID_SEGMENT	0x08	/* Segmentation fragment */
#define	PID_APPLETALK   0x0A
#define	PID_APPLEARP	0x0B
#define PID_IP			0x0C
#define PID_ARP		0x0D
#define	PID_RARP		0x0E
#define	PID_NETROM	0x0F

/* Segment number flags */
#define	SEG_FIRST	0x80	/* Denotes first segment */
#define	SEG_LEFT		0x7f	/* Mask for # remaining segs */

/* L4 opcodes - in lower nybble of opcode byte */
#define	L4_OP_PID	0x00
#define	L4_OP_CREQ	0x01
#define	L4_OP_CACK	0x02
#define	L4_OP_DREQ	0x03
#define	L4_OP_DACK	0x04
#define	L4_OP_INFO	0x05
#define	L4_OP_IACK	0x06
#define	L4_OP_RSET	0x07	// Link reset (G8PZT)
#define	L4_OP_CRQX	0x08	// Extended CREQ (G8PZT)
#define	L4_OP_MASK	0x0f

/* L4 Flags - in upper nybble of opcode byte */
#define	L4_FLG_CHOKE	0x80
#define	L4_FLG_NAK	0x40
#define	L4_FLG_MORE	0x20
#define	L4_FLG_MASK	0xF0

/*******************************************************************/
/* Purpose:		Decode and display an AX25 callsign.
 * Called by:	main() and decodeDigipeaters().
 * Arguments:	Pointer to AX25-format callsign in a byte buffer
 * Affects:		Stdout only
 * Assumes:		Buffer pointed by bp is at least 7 bytes long
 * Returns:		Pointer to SSID byte in the buffer
 * Created:		Sat 20th Jan 2024
 * Modified:	x
 * Notes:		x	*/
/*******************************************************************/

static byte *decodeCallsign (byte *bp)
	{
	int	i, ssid;

	for (i = 0; i < 6; i++, bp++)
		if (((*bp >> 1) & 0x7f) != ' ') putchar ((*bp >> 1) & 0x7f);

	if ((ssid = ((*bp >> 1) & 15)) > 0) printf ("-%d", ssid);

	return (bp);
	}

/*******************************************************************/
/* Purpose:		Decode and display digipeater list
 * Called by:	main() only.
 * Arguments:	Pointer to start of digipeater list,
 * 				remaining frame length.
 * Actions:		Displays comma-delimited list of callsigns, with '*'
 * 				appended to the callsigns which have been digipeated.
 * Affects:		Stdout only.
 * Returns:		Total length of digipeater list in bytes
 * Created:		Sat 20th Jan 2024
 * Modified:	x
 * Notes:		x	*/
/*******************************************************************/

static int decodeDigipeaters (byte *bp, int len)
	{
	while (len >= 7)
		{
		len -= 7;
		putchar (',');
		bp = decodeCallsign (bp);
		if (*bp & REPEATED) putchar ('*');
		if (*bp & EXTENSION) break;	// end of digis
		bp++;	// Point to next callsign
		}

	return (len);
	}

// Trivial: used in displayText() and decodeL4
static void putHex (int value)
	{
	printf ("{0x%02x}", value);
	}

/*******************************************************************/
/* Purpose:		Display the text payload of AX25 L2 or L4 frame.
 * Called by:	main() and decodeNetromLayer4().
 * Arguments:	Pointer to the start of text (not null terminated!),
 * 				length of text.
 * Actions:		Displays text, substituting packet EOL with Linux EOL,
 * 				and unprintable characters as {hex}.
 * Affects:		stdout only.
 * Returns:		0 if no error, -1 if error
 * Created:		Sat 20th Jan 2024
 * Modified:	x
 * Notes:		*/
/*******************************************************************/

static void displayText (byte *bp, int len)
	{
	int	ch;

	while (len-- > 0)
		{
		// Packet uses \r for EOL, so ignore \n & convert \r to \n
		if ((ch = *bp++) == '\n') continue;
		if (ch == '\r') ch = '\n';
		else
			{
			if (ch >= 32 && ch <= 127) putchar (ch);
			else putHex (ch);
			}
		}

	putchar ('\n');
	}

/*******************************************************************/
/* Purpose:		Get a Netrom "alias" into a string.
 * Called by:	decodeNodesBroadcast()
 * Arguments:	Pointer to the start of alias (not null terminated!),
 * 				Pointer to a string to write the result to.
 * Assumes:		There are at least 6 bytes in the source buffer, and
 * 				at least 7 in the output string.
 * Actions:		Copies at most 6 characters from source buffer bp to
 * 				destination string "alias", stopping at the first
 * 				whitespace. The output string is null terminated.
 * Affects:		Supplied string only.
 * Returns:		Pointer to the string containing the alias
 * Created:		Sat 20th Jan 2024
 * Modified:	x
 * Notes:		*/
/*******************************************************************/

char *getAlias (byte *bp, char *alias)
	{
	int			i;
	byte		ch;

  for (i = 0; i < 6; i++)
     {
     if (isspace (ch = *bp++)) break;
     alias [i] = ch;
     }

  alias [i] = 0;

  return (alias);
  }

/*******************************************************************/
/* Purpose:		Decode and display Netrom Layer 4.
 * Called by:	decodeNetrom() only.
 * Arguments:	Pointer to the start of L4 header,
 * 				length of header+payload.
 * Affects:		stdout only.
 * Created:		Sun 21st Jan 2024 v1.2
 * Modified:	x
 * Notes:		*/
/*******************************************************************/

static void decodeNetromLayer4 (byte *bp, int len)
	{
	int		l4opcode, l4flags, minhdr;
	char		*winstr = " w=%d\n         ";	// indent 9 spaces

	if (len < 5)
		{
		printf("  (Bad L4 header)\n");
		return;
		}

	l4opcode = bp [4] & L4_OP_MASK;
	l4flags = bp [4] & L4_FLG_MASK;

	switch (l4opcode)
		{
		case L4_OP_PID:
			// Protocol extension - beyond the scope of this applet?
			printf (" pf=%02x prot=%02x\n", bp[0], bp[1]);
			return;

		case L4_OP_CREQ:
		case L4_OP_CRQX:
			minhdr = 20;
			break;

		case L4_OP_CACK:
			minhdr = 6;
			break;

		default:
			minhdr = 5;
			break;
		}

	if (len < minhdr )
		{
		printf("  (Bad L4 header)\n");
		return;
		}

	printf (" cct=%02X%02X", bp[0], bp[1]);

	switch (l4opcode)
		{
		case L4_OP_CREQ:
			if (len < 20)
				{
				}
			printf (" <CONN REQ>");
			printf (winstr, bp [5]);	// proposed window
			decodeCallsign (bp+6);		// Source call
			printf (" at ");
			decodeCallsign (bp+13);		// Source node

			// BPQ extensions - up to 4 bytes, first 2 are L4T1
			if (len > 21) printf (" t/o=%d ", bp[20] + (256*bp [21]));
			if (len > 22) putchar (bp [22]);	// 'Z' = BPQ "spy" flag
			if (len > 23)
				{
				putchar (' ');
				putHex (bp [23]);
				}
			break;

		case L4_OP_CACK:
			printf (" <CONN ");
			if (l4flags & L4_FLG_CHOKE) printf ("NAK> ");
			else
				{
				printf ("ACK> w=%d my cct=%02X%02X ",
					bp [5], bp [2], bp [3]);
				}
			break;

		case L4_OP_DREQ:
			printf (" <DISC REQ> ");
			break;

		case L4_OP_DACK:
			printf (" <DISC ACK> ");
			break;

		case L4_OP_INFO:
			printf (" <INFO S%d R%d> ", bp [2], bp [3]);
			break;

		case L4_OP_IACK:
			printf (" <INFO ACK R%d> ", bp [3]);
			break;

		case L4_OP_RSET:
			printf (" <RSET> my_cct=%02X%02X", bp [2], bp [3]);
			break;

		case L4_OP_CRQX:
			printf (" <CONN REQX> svc=%d", bp[2]+(256*bp[3]));
			printf (winstr, bp [5]);	// proposed window
			decodeCallsign (bp+6);		// Source call
			printf (" at ");
			decodeCallsign (bp+13);		// Source node
			if (len > 20) printf ("flg=%u", bp[20]);	// flags
			break;
		}	/* end of switch */

	if ((l4flags & L4_FLG_CHOKE) && l4opcode != L4_OP_CACK)
		printf ("<CHOKE>");

	if (l4flags & L4_FLG_NAK) printf ("<NAK>");
	if (l4flags & L4_FLG_MORE) printf ("<MORE>");

	putchar ('\n');

	if (l4opcode != L4_OP_INFO) return;

	printf ("  DATA: ");

	displayText (bp+5, len-5);

	putchar ('\n');
	}

/*******************************************************************/
/* Purpose:		Decode and display Netrom Nodes broadcast.
 * Called by:	decodeNetrom() only.
 * Arguments:	Pointer to the start of broadcast data,
 * 				length of data.
 * Affects:		stdout only.
 * Created:		Sat 20th Jan 2024
 * Modified:	x
 * Notes:		*/
/*******************************************************************/

static void decodeNodesBroadcast (byte *bp, int len)
	{
	char tmp [30];

	printf("NODES broadcast from %s len = %d\n",
		getAlias (bp, tmp), len);

	bp += 6;
	len -= 6;

	while (len >= 21)
		{
		printf ("  ");
		decodeCallsign (bp);	// Nodecall
		printf (":%s via ", getAlias (bp+7, tmp));
		decodeCallsign (bp+13);	// via node
		printf (" qlty=%d\n", bp[20]);
		bp += 21;
		len -= 21;
		}
  }

/*******************************************************************/
/* Purpose:		Decode and display Netrom Layer 3.
 * Called by:	main() only, for PID==0xcf.
 * Arguments:	Pointer to the start of L3 header,
 * 				length of header+payload.
 * Actions:		Decodes L3, then L4 and any L4 text payload
 * Affects:		stdout only.
 * Created:		Sat 20th Jan 2024
 * Modified:	x
 * Notes:		*/
/*******************************************************************/

static void decodeNetrom (byte *bp, int len, bool bcast)
	{
	if (*bp == 0xff)  // Nodes b/cast or INP3 routing info frame
		{
		if (bcast) decodeNodesBroadcast (bp+1, len-1);
		///else trace inp3 rif - to be done - if you want?
		return;
		}

	if (*bp == 0xFE)	// Poll for nodes broadcast
		{
		printf ("  Routing poll");
		if (len > 1)
			{
			char	alias [10];

			// Display the sender's s alias
			printf (" from %s\n", getAlias (bp+1, alias));
			}
		else printf (" (bad)\n");

		return;
		}

	if (len < 15)
		{
		printf ("(L3 header too short)\n");
		return;
		}

	printf ("NTRM: ");				// Indent the display
	decodeCallsign (bp);				// L3 source callsogn
	printf (" to ");
	decodeCallsign (bp+7);			// L3 dest callsign
	printf (" ttl=%d", bp[14]);	// L3 TTL

	bp += 15;
	len -= 15;

	decodeNetromLayer4 (bp, len);
	}

/*******************************************************************/
/* Purpose:		Main function
 * Called by:	Don't ask me, I don't understand these things!
 * Arguments:	Argument count, argument list
 * Actions:		Reads stdin until EOF, then decodes the data as AX25
 * 				sending it to stdout.
 * Affects:		stdin, stdout
 * Returns:		0 if no error, -1 if error
 * Created:		Sat 20th Jan 2024 as v1.0
 * Modified:	x
 * Notes:		Probably could add switches to control the output
 * 				format and verbosity, but I'm out of time today.
 * */
/*******************************************************************/

int main (int argc, char *argv[])
	{
	byte	frameBuf[MAX_FRAME], *bp;
	int	i, ch, len=0;
	int	src_ssid, dst_ssid, ctrl, frametype, modulo=8;
	int	crpf, pfbit, pollFinal, pid, frag, segnum;

	// Assemble the frame in frameBuf
	while ((ch = fgetc (stdin)) != EOF && len < MAX_FRAME)
		frameBuf [len++] = ch;

	bp = frameBuf;

	if (len == 2)
		{
		// Ack for a previous sent frame
		printf ("AckRply: [%d]\n", (bp[1] << 8) + bp[0]);
		return (0);
		}

	/* If it's an incoming frame, the AX25 starts at offset 0.
	 * If it's an outgoing frame with ackmode, the first two bytes are
	 * a 16-bit serial number, sent low-byte first, and the AX25
	 * starts at offset 2. As we are given no information as to the
	 * direction, we have to guess.
	 * It has been observed that the serial numbers are very low,
	 * meaning that bp[1] is usually 0 on an ackmode frame. This
	 * can never occur on raw AX25. Find a better way to do this!
	 * */
	if (len > 1 && (bp [1] == 0))
		{
		printf ("AckRqst: [%d] ", bp [0]);
		bp += 2;
		len -= 2;
		}

	// Is the frame long enough to be valid
	if (len < 15)
		{
		// No, it's a duffer!
		printf ("\n%d bytes is too short to be valid AX25!\n", len);
		return (-1);
		}

	// Decode and display source call
	src_ssid = *decodeCallsign (bp+7);

	printf (" > ");

	// decode and display dest call
	dst_ssid = *decodeCallsign (bp);

	bp += 14;
	len -= 14;

	// If there are digipeaters, decode and display them
	if ((src_ssid & EXTENSION) == 0)
		{
		i = decodeDigipeaters (bp, len);
		bp += i;
		len -= i;
		}

	// There should be at least a control byte
	if (len < 1)	return (-1);

	ctrl = *bp++;
	len--;

	if ((src_ssid & EAX25) == 0)
		{
		modulo = 128;

		if ((ctrl & 3) != U)		// If not a U frame...
			{
			ctrl |= (((int)*bp) << 8);		// there's a 2nd ctrl byte
			len--;
			}
		}

	// Command / response / poll / final flags
	crpf = 0;
	if (dst_ssid & CMDRSP) crpf |= COMMAND;
	if (src_ssid & CMDRSP) crpf |= RESPONSE;

	pfbit = ((modulo == 128) & ((ctrl & 3) != U)) ? EPF : PF;
	pollFinal = (ctrl & pfbit);

	printf (" <");

	// Work out the frame type
	if ((ctrl & 1) == 0) frametype = I;
	else if ((ctrl & 2) == 0) frametype = (ctrl & 15);
	else frametype = ((ctrl & ~PF) & 0xff);

	switch (frametype)
		{
		case SABM:	printf ("C");					break;
		case SABME: printf ("SABME");				break;
		case DISC:	printf ("D");					break;
		case DM:		printf ("DM");					break;
		case UA:		printf ("UA");					break;
		case FRMR:	printf ("FRMR");				break;
		case UI:		printf ("UI");					break;
		case RR:		printf ("RR");					break;
		case RNR:	printf ("RNR");				break;
		case REJ:	printf ("REJ");				break;
		case I:		printf ("I");					break;
		default:		printf ("ctrl=%d", ctrl);	break;
		}

  // Display the C/R & P/F bits
	switch (crpf & (COMMAND | RESPONSE))
		{
		case COMMAND:
			printf (" C");
			if (pollFinal) printf (" P");
			break;

		case RESPONSE:
			printf (" R");
			if (pollFinal) printf (" F");
			break;

		default:
			printf(" V1");	// Old protocol
			if (pollFinal) printf (" P");
			break;
		}

	// Send and receive sequence numbers
	if ((ctrl & 3) != U)
		{
		int	seqMask = modulo -1;

		printf (" R%d",
			((seqMask == 127) ? (ctrl >> 9) : (ctrl >> 5)) & seqMask);
		if (frametype == I)
			printf (" S%d", (ctrl >> 1) & seqMask);
		}

	printf (">");

	if ((src_ssid & DAMA) == 0) printf (" [DAMA]");

	if (frametype == FRMR)
		{
		// I'm too lazy to decode this today!
		putchar ('\n');
		return (0);
		}

	// If it's not a dats-bearing frame, we're done
	if (frametype != I && frametype != UI)
		{
		putchar ('\n');
		return (0);
		}

	/* Frame contains data portion */

	pid = *bp++;	/* Get pid & point at first data byte */
	len -= 1;

	if (pid == PID_SEGMENT)
		{
		frag = 1;
		segnum = *bp++;
		len -= 1;
		if (segnum & SEG_FIRST)
			{
			pid = *bp++;
			len -= 1;
			}
		}
	else frag = 0;

	if (frag) printf (" [%ssegment: (%d left)]",
			(segnum & SEG_FIRST) ? "first " : "", segnum & SEG_LEFT);

	printf (" ilen=%d pid=%d", len, pid);

	switch (pid & PID_MASK)
		{
		case PID_SEGMENT:
			/* It's a non-first segment, so don't display a l3 type
			 * since we have no idea what it is
			 */
			printf (" SEG\n");
			break;

		case PID_NO_L3:
			printf (" DATA:\n");
			displayText (bp, len);
			return (0);

		case PID_NETROM:
			printf (" NET/ROM\n  ");
			decodeNetrom (bp, len, (frametype == UI));
			return (0);

		case PID_IP:
			printf (" IP\n");
			break;

		case PID_ARP:
			printf (" ARP\n");
			break;

		default:
			putchar ('\n');
			break;
		}	// end of switch


	if (len < 0) return (-1);

	return (0);
	}
