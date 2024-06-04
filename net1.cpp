#define NULL 0
#define TCPDUMP_MAGIC 0xa1b2c3d4 /* Tcpdump Magic Number (Preamble) */
#define PCAP_VERSION_MAJOR 2     /* Tcpdump Version Major (Preamble) */
#define PCAP_VERSION_MINOR 4     /* Tcpdump Version Minor (Preamble) */
#define DLT_NULL 0               /* Data Link Type Null */
#define DLT_EN10MB 1             /* Data Link Type for Ethernet II 100 MB and above */
#define DLT_EN3MB 2              /* Data Link Type for 3 Mb Experimental Ethernet */

// Ethernet Header
#define ETHER_ADDR_LEN 6

#include <winsock2.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;

FILE *input;
FILE *output;

typedef struct packet_header
{
    unsigned int magic;           /* Tcpdump Magic Number */
    unsigned short version_major; /* Tcpdump Version Major */
    unsigned short version_minor; /* Tcpdump Version Minor */
    unsigned int thiszone;        /* GMT to Local Correction */
    unsigned int sigfigs;         /* Accuracy of timestamps */
    unsigned int snaplen;         /* Max Length of Portion of Saved Packet */
    unsigned int linktype;        /* Data Link Type */
} hdr;

typedef struct packet_timestamp
{
    unsigned int tv_sec;  /* Timestamp in Seconds */
    unsigned int tv_usec; /* Timestamp in Micro Seconds */
    unsigned int caplen;  /* Total Length of Packet Portion (Ethernet Length until the End of Each Packet) */
    unsigned int len;     /* Length of the Packet (Off Wire) */
} tt;

typedef struct ether_header
{
    unsigned char edst[ETHER_ADDR_LEN]; /* Ethernet Destination Address */
    unsigned char esrc[ETHER_ADDR_LEN]; /* Ethernet Source Address */
    unsigned short etype;               /* Ethernet Protocol Type */
} eth;

int main(int argc, char *argv[])
{
    unsigned int remain_len = 0;
    unsigned char temp = 0, hlen, version, tlen;
    int i, count = 0;
    struct packet_header hdr;   /* Initialize Packet Header Structure */
    struct packet_timestamp tt; /* Initialize Timestamp Structure */
    struct ether_header eth;    /* Initialize Ethernet Structure */
    unsigned char buff, array[1500];
    int classb = 0;
    // an array to store the packet number that belongs to class B
    vector<int> classb_packets;

    input = fopen("abc.pcap", "rb");  /* Open Input File */
    output = fopen("xyz.pcap", "wb"); /* Open Output File */

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        printf("WSAStartup failed with error: %d\n", WSAGetLastError());
        return 1;
    }

    if (input == NULL)
    {
        cout << "Cannot open saved windump file" << endl;
    }
    else
    {
        fread((char *)&hdr, sizeof(hdr), 1, input);   /* Read & Display Packet Header Information */
        fwrite((char *)&hdr, sizeof(hdr), 1, output); /* Write Packet Header to Output File */

        cout << "\n******************** PACKET HEADER *********************\n" << endl;
        cout << "Preamble " << endl;
        cout << "Packet Header Length : " << sizeof(hdr) << endl;
        cout << "Magic Number : " << hdr.magic << endl;
        cout << "Version Major : " << hdr.version_major << endl;
        cout << "Version Minor : " << hdr.version_minor << endl;
        cout << "GMT to Local Correction : " << hdr.thiszone << endl;
        cout << "Jacked Packet with Length of : " << hdr.snaplen << endl;
        cout << "Accuracy to Timestamp : " << hdr.sigfigs << endl;
        cout << "Data Link Type (Ethernet Type II = 1) : " << hdr.linktype << endl;

        // Task 1 : Read the input file abc.pcap
        /* Use While Loop to Set the Packet Boundary */
        while (fread((char *)&tt, sizeof(tt), 1, input))
        { /* Read & Display Timestamp Information */
            ++count;
            cout << "******************** TIMESTAMP & ETHERNET FRAME *********************" << endl;
            cout << "Packet Number: " << count << endl; /* Display Packet Number */
            cout << "The Packets are Captured in : " << tt.tv_sec << " Seconds" << endl;
            cout << "The Packets are Captured in : " << tt.tv_usec << " Micro-seconds" << endl;
            /* Use caplen to Find the Remaining Data Segment */
            cout << "The Actual Packet Length: " << tt.caplen << "Bytes" << endl;
            cout << "Packet Length (Off Wire): " << tt.len << "Bytes" << endl;
            fread((char *)&eth, sizeof(eth), 1, input); /* Read & display ethernet header information */
            cout << "Ethernet Header Length : " << sizeof(eth) << " bytes" << endl;

            printf("\n\nC Cout\n\n");
            cout << "MAC Address " << eth.esrc[0] << " " << eth.esrc[1] << endl;

            for (i = 0; i < tt.caplen - 14; i++) //to iterate through the packet data
            {
                fread((char *)&buff, sizeof(buff), 1, input);
                array[i] = buff;
            }

            // Task 2 AND 3 : Capture only source IPv4 address that belong to Class B only AND Capture Destination IP address that belong to Class B only

            // Convert etype from network byte order to host byte order
            unsigned short etype = ntohs(eth.etype);

            if (etype == 0x0800)
            {
                cout << "IPv4 Packet" << endl;

                // Print the source and destination IP addresses for checking purposes
                printf("\n\nSource IP Address\n");
                printf(" %d.%d.%d.%d\n", array[12], array[13], array[14], array[15]);
                printf("\nDestination IP Address\n");
                printf(" %d.%d.%d.%d\n", array[16], array[17], array[18], array[19]);

                if ((array[12] >= 128 && array[12] <= 191) && (array[16] >= 128 && array[16] <= 191))
                {
                    cout << "\n" << endl;
                    printf("Both the Source and Destination IP Addresses belong to Class B\n");
                    classb++;

                    // Task 4 : Store the output file xyz.pcap
                    fwrite((char *)&tt, sizeof(tt), 1, output);   /* The timestamp */
                    fwrite((char *)&eth, sizeof(eth), 1, output); /* The ethernet header */
                    fwrite(array, 1, tt.caplen - 14, output);     /* The data packet */

                    // Store the packet number that belongs to class B
                    classb_packets.push_back(count);
                }
                else
                {
                    cout << "\n" << endl;
                    printf("Either the Source or Destination IP Address does not belong to Class B\n");
                }
            }
            else if (etype == 0x86DD)
            {
                // IPv6 packet
                cout << "IPv6 Packet" << endl;
                cout << "There is no classing in IPv6\n";
                continue;
            }

            printf("\n");
        } // end while

        // Printing the number of packets that belong to class B for both source and destination IP addresses
        // for checking purposes
        cout << "-----------------------------------------------------------" << endl;
        printf("Number of Packets with Source IP Address and Destination IP Address in Class B: %d\n", classb);
        cout << "\n";
        // Printing the packet numbers that belong to class B for both source and destination IP addresses
        // for checking purposes
        cout << "The packet numbers that have both source and destination IP addresses in Class B are: ";
        cout << "\n";
        for (int i = 0; i < classb_packets.size(); i++)
        {
            cout << classb_packets[i] << " ";
        }
        cout << "\n";
        cout << "-----------------------------------------------------------" << endl;
    } // end main else

    // Clean up
    WSACleanup();

    fclose(input);  // Close input file
    fclose(output); // Close output file
    return (0);
}
