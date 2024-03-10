#include <stdio.h>
#include <stddef.h>

typedef struct {
    char* pointer;
    char count_times17;
    char count;
} my_struct;

my_struct ** str_arr;

void fill_global_with_structs(void *rwx)

{
my_struct *p3;
  int i;
  
  str_arr = (my_struct **)malloc(0xc0);
  for (i = 0; i < 0x17; i = i + 1) {
    p3 = (my_struct *)malloc(0x10);
    p3->pointer = (char *)((long)rwx + (long)(i * 0x11));
    p3->count_times17 = (char)i * '\x11';
    p3->count = (char)i;
    str_arr[i] = p3;
  }
  str_arr[0x17] = (my_struct *)0x0;
  return;
}


int main(int argc,char **args)
{
  void *rwx;
  size_t arg_len;
  int i;
  my_struct *pStruct;
  my_struct *pStruct2;
  
  rwx = mmap((void *)0x0,4096,7,0x22,-1,0);
  fill_global_with_structs(rwx);

//                        p_to_char                                       XREF[1]:     main:00100aba(R)  
// 00302010 78 0c 10        ds *       DAT_00100c78                                     = 56h    V
//          00 00 00 
//          00 00
//                      //
//                      // .bss 
//                      // SHT_NOBITS  [0x202018 - 0x202027]
//                      // ram:00302018-ram:00302027
//                      //
//                      DAT_00302018                                    XREF[6]:     FUN_001007d0:001007d0(*), 
//                                                                                   FUN_00100810:00100810(*), 
//                                                                                   FUN_00100810:00100817(*), 
//                                                                                   _FINI_0:00100860(R), 
//                                                                                   _FINI_0:00100889(W), 
//                                                                                   _elfSectionHeaders::00000610(*)  
// 00302018                 undefined1 ??

  memcpy(rwx,p_to_char,757);
  if (argc != 2) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  arg_len = strlen(args[1]);
  if (arg_len != 23) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  shuffle_structs();
  for (i = 0; i < 23; i = i + 1) {
    pStruct = str_arr[i];
    pStruct2 = str_arr[(long)i + 1];
    if (pStruct2 == (my_struct *)0x0) {
      (*(code *)pStruct->pointer)(args[1] + (byte)pStruct->count,rwx,0);
    }
    else {
      (*(code *)pStruct->pointer)
                (args[1] + (byte)pStruct->count,pStruct2->pointer,(int)pStruct2->count_times17);
    }
  }
  puts("What are you waiting for, go submit that flag!");
  return 0;
}


