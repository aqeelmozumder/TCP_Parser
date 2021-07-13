Dependencies of this file:
                          basic_structures.py
                      Therefore, please make sure to have basic_structures.py in the same directory as it is a dependency

How to compile and run the file:
                           python3 tcp_cap.py <capture_filename.cap>
Description:
         The idea of this file is to be broken down into 4 sections. The overview of the sections are decribed as follows:
             Section 1 will be where all the data is unpacked by reading the cap file
             Section 2 is required to list the unique tuples in a connection list
             Section 3 is the longest section as this section has nested loops to search for complete connections in the connection list and will print out part A and B of the assignment
             Section 4 will only print part C and D of the assignment