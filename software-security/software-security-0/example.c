undefined8 main(void)
{
  int iVar1; // Variable to store the result of memcmp
  size_t sVar2; // Variable to store the length of the input string
  long in_FS_OFFSET; // Offset for the stack canary
  size_t input_len; // Variable to store the adjusted length of the input string
  undefined8 i; // Counter for the XOR loop
  byte usr_input [264]; // Buffer to store the user input
  long local_10; // Variable to store the original stack canary value
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28); // Store the original stack canary value
  memset(usr_input,0,0x100); // Initialize the input buffer with zeros
  do {
    printf(&DAT_00102026); // Print a prompt message
    fgets((char *)usr_input,0x100,stdin); // Read user input
    sVar2 = strlen((char *)usr_input); // Get the length of the input string
    if (sVar2 != 0) { // If the input string is not empty
      input_len = sVar2; // Store the length of the input string
      if (usr_input[sVar2 - 1] == 10) { // If the last character is a newline
        input_len = sVar2 - 1; // Adjust the length of the input string
        usr_input[sVar2 - 1] = 0; // Replace the newline character with a null character
      }
      if (input_len == 0xe) { // If the length of the input string is 14
        for (i = 0; i < 0xe; i = i + 1) { // For each character in the input string
          usr_input[i] = usr_input[i] ^ key[i]; // XOR the character with the corresponding byte in the key
        }
        iVar1 = memcmp(usr_input,flag,0xe); // Compare the result with the flag
        if (iVar1 == 0) { // If the result matches the flag
          puts(&DAT_0010205b); // Print a success message
          if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) { // If the stack canary has been modified
                    /* WARNING: Subroutine does not return */
            __stack_chk_fail(); // Terminate the program with a stack smashing detected error
          }
          return 0; // Exit the program
        }
      }
    }
    puts(&DAT_0010203f); // Print a failure message
  } while( true ); // Repeat indefinitely
}

