//
// Created by Phillip Romig on 7/16/24.
//
#include <iostream>
#include <fstream>
#include <vector>
#include <sys/socket.h>
#include <system_error>
#include <unistd.h>
#include <array>
#include <cstring>

#include "timerC.h"
#include "unreliableTransport.h"
#include "logging.h"

#define WINDOW_SIZE 10
int main(int argc, char *argv[])
{

    // Defaults
    uint16_t portNum = 12345;
    std::string hostname = "isengard.mines.edu";
    std::string inputFilename = "";

    int opt;
    try
    {
        int signedTemp;
        while ((opt = getopt(argc, argv, "f:h:p:d:")) != -1)
        {
            switch (opt)
            {
            case 'p':
                signedTemp = std::stoi(optarg);
                if ((signedTemp < 12000) or (signedTemp > 13000))
                {
                    std::cerr << "To deal with isengard's firewall, port numbers must be between 12,000 and 13,000." << std::endl;
                    exit(EXIT_FAILURE);
                }
                portNum = signedTemp;
                break;

            case 'h':
                hostname = optarg;
                break;
            case 'd':
                LOG_LEVEL = std::stoi(optarg);
                if ((LOG_LEVEL < 0) or (LOG_LEVEL > 6))
                {
                    std::cerr << "Debug level must be between 0 and 6" << std::endl;
                    std::cout << "Usage: " << argv[0] << " -f filename [-h hostname] [-p port] [-d debug_level]" << std::endl;
                    exit(EXIT_FAILURE);
                }
                break;
            case 'f':
                inputFilename = optarg;
                break;
            case '?':
            default:
                std::cout << "Usage: " << argv[0] << " -f filename [-h hostname] [-p port] [-d debug_level]" << std::endl;
                break;
            }
        }
    }
    catch (std::exception &e)
    {
        FATAL << "Invalid command line arguments: " << e.what() << ENDL;
        std::cout << "Usage: " << argv[0] << " -f filename [-h hostname] [-p port] [-d debug_level]" << std::endl;
        exit(1);
    }

    if (inputFilename == "")
    {
        FATAL << "Invalid command line arguments: -f filename is required" << ENDL;
        exit(EXIT_FAILURE);
    }
    TRACE << "Command line arguments parsed." << ENDL;
    TRACE << "\tServername: " << hostname << ENDL;
    TRACE << "\tPort number: " << portNum << ENDL;
    TRACE << "\tDebug Level: " << LOG_LEVEL << ENDL;
    TRACE << "\tOutput file name: " << inputFilename << ENDL;

    //----- Open the input file -----

    // Open the file using ifstream in binary mode
    std::ifstream inputFile(inputFilename, std::ios::binary);

    // Check if the file opening fails - throw an error if so
    if (!inputFile){
        throw std::runtime_error("Cannot open " + inputFilename);
    }

    try{

        //----- Initialize your timer, datagram buffer, transport layer etc. -----
        // Create the unreliableTransport object
        unreliableTransportC serverConnection(hostname, portNum);

        // Create the timer object - using 50 ms to start
        timerC timer(50);

        // Create the send packet array
        std::array<datagramS, WINDOW_SIZE> sndpkt;

        // Create the base values and next sequence number values
        uint32_t base = 0;
        uint32_t nextSeqNumber = 0;

        // Counter variable and maximum timeout variable for EOF loss checks
        int consecutiveTimeouts = 0;
        const int MAX_TIMEOUTS_AT_EOF = 15; // Allowed timeouts at end of file. Allows a decent amount of timeouts to occur before ending the server

        // Value that indicates if the datagram has reached its end
        bool endOfFileReached = false;

        bool finished = false;

        while (!finished){
            //----- Is there space in the window? If so, read data from file and send it -----
            if (!endOfFileReached && (nextSeqNumber < base + WINDOW_SIZE)){
                // Set the packet size
                datagramS &packet = sndpkt[nextSeqNumber % WINDOW_SIZE];

                // Clear out the current packet
                memset(&packet, 0, sizeof(packet));

                // Read in from the file
                inputFile.read(reinterpret_cast<char *>(packet.data), MAX_PAYLOAD_LENGTH);

                // If the gcount is zero, set end of file boolean to true
                if (inputFile.gcount() == 0){
                    endOfFileReached = true;
                }

                // Set the packet payload length to the total amout read in from the file
                packet.payloadLength = inputFile.gcount();

                // Set the sequence number
                packet.seqNum = nextSeqNumber;

                // Compute the checksum, then store is
                packet.checksum = computeChecksum(packet);

                // Send the packet
                serverConnection.udt_send(packet);

                // If the base = the next sequence number, start the timer
                if (base == nextSeqNumber){
                    timer.start();
                }

                // Increment the next
                nextSeqNumber++;
            }

            //----- Are there acknowledgments in from the server. If so, process them. -----
            // Create a datagramS ack variable
            datagramS ack;

            // If the server connection received a value greater than a one, investigate the ack
            if (serverConnection.udt_receive(ack) > 0){
                // Validate the checksum and if the ackNum + 1 is larger than the current base, if true, increase the base
                if (validateChecksum(ack) && ((ack.ackNum + 1) > base)){
                    // Increase the base
                    base = ack.ackNum + 1;

                    // Reset the timeout counter since base has updated
                    consecutiveTimeouts = 0;

                    // Verify there isn't a bogus ACK
                    if (ack.ackNum < nextSeqNumber){
                        // Skip the packet
                        continue;
                    }

                    // If the base equals the next sequence number, stop the timer
                    if (base == nextSeqNumber){
                        timer.stop();
                    }
                    // Else, restart the timer
                    else{
                        timer.stop();
                        timer.start();
                    }
                }
            }

            //----- Have we has the timer gone off? -----
            // Check if the timer is still running and if it has timed out
            if (timer.isRunning() && timer.timeout()){
                // Increase the consecutive timeout counter
                consecutiveTimeouts++;

                // Check if the end of the file has been reached and if the consecutive timout limit has been reached
                if (endOfFileReached && (consecutiveTimeouts >= MAX_TIMEOUTS_AT_EOF)){
                    finished = true;
                }
                else{

                    // restart the timer
                    timer.stop();
                    timer.start();

                    // Resend every packet from base to nextSeqNum - 1
                    for (uint32_t seq = base; seq < nextSeqNumber; seq++){
                        datagramS &packet = sndpkt[seq % WINDOW_SIZE];

                        serverConnection.udt_send(packet);
                    }
                }
            }

            // Check if end of fiule has been reached and if the base equals the next sequence number. Set finished to true if so
            if (endOfFileReached && (base == nextSeqNumber)){
                finished = true;
            }
        }
    }
    catch (std::exception &e){
        FATAL << "Error: " << e.what() << ENDL;
        exit(1);
    }

    return 0;
}
