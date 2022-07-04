#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <wmmintrin.h>
#include <vector>

// Alignment helper
#if !defined (ALIGN16)
# if defined (__GNUC__)
# define ALIGN16 __attribute__ ( (aligned (16)))
# else
# define ALIGN16 __declspec (align (16))
# endif
#endif

std::vector<uint8_t> f;

int main(){
  return 0;
}