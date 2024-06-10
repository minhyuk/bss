/*
 * Function: usage
 * Description: Displays the usage instructions for the program.
 * Parameters:
 *     - name: the name of the program
 * Returns: an exit status
 */
int usage(char *);

/*
 * Function: l2dos
 * Description: Performs L2CAP layer denial-of-service (DoS) attack by sending crafted packets.
 * Parameters:
 *     - bdstr_addr: Bluetooth device address
 *     - cmdnum: L2CAP command number
 *     - siz: size of the packet
 *     - pad: padding byte
 */
void l2dos(char *, int, int, char);

/*
 * Function: l2fuzz
 * Description: Conducts L2CAP layer fuzzing by sending random packets to test vulnerability.
 * Parameters:
 *     - bdstr_addr: Bluetooth device address
 *     - maxsize: maximum size of the packet
 *     - maxcrash: maximum crash count
 */
void l2fuzz(char *, int, int);

/*
 * Function: code2define
 * Description: Maps L2CAP command codes to corresponding string definitions.
 * Parameters:
 *     - code: L2CAP command code
 * Returns: string representation of the code
 */
char *code2define(int);

/*
 * Function: main
 * Description: Entry point of the program to initiate Bluetooth protocol testing.
 * Parameters:
 *     - argc: number of command line arguments
 *     - argv: array of command line arguments
 * Returns: program exit status
 */
int main(int, char **)
*/
