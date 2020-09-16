#ifndef HAMMING_PARAMETERS_H
#define HAMMING_PARAMETERS_H

//JAIN_K corresponds to N in the rank paper
//JAIN_N corresponds to K in the rank paper
//JAIN_L corresponds to PI in the rank paper
//JAIN_V corresponds to MI in the rank paper

#define JAIN_K 2640                     // Jain Paper Code Length
#define JAIN_L 128                      // Length of randomness
#define JAIN_V 1192                     // Length of the message
#define JAIN_N (JAIN_L + JAIN_V)        // Code dimension
#define W 284


#define I 3
#define J 4

#endif //HAMMING_PARAMETERS_H
