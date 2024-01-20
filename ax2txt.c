/*
 * Program:	AX2TXT
 * Purpose:	Decode ax25 frames from stdin to stdout.
 * Created: Sat 20th Jan 2024, by Paula G8PZT
 * Notes:	Very quick and dirty, could be improved!
 * Version:	1.1, 20/1/2024
 * Modified:
 * 20/1/24	1.1	Corrected AckRqst / AckRply display.
 *
 */

#include <stdio.h>


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

/*******************************************************************/
/* Purpose:		Display the text portion of a NO-L3 AX25 frame.
 * Called by:	main() only.
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
			else printf ("{0x%02x}", ch);
			}
		}

	putchar ('\n');
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
		printf ("AckRqst [%d] ", bp [0]);
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
			///decodeNetrom (bp, len, (frametype == UI);
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
