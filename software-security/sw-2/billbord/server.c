#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <link.h>
#include <dlfcn.h>

#include "module.h"


#define BACKLOG 32
#define MAX_ARGC 256

#define logf(...) fprintf(stderr, __VA_ARGS__)



module_t module;

void (*initialize_module)(module_t* m, registration_function r);

void module_info(int argc, char* argv[]) {
    printf("************************************\n");
    printf("Information about the loaded module:\n");
    printf("Name: %s\nBase address: %p\n", module.name, (void*) module.base);
    printf("************************************\n");
}

void register_command(const char* name, const char* usage, const char* desc, handle_command_function function) {
    command_t* command = malloc(sizeof(command_t));
    command->name = name;
    command->usage = usage;
    command->description = desc;
    command->function = function;
    command->next = NULL;

    if (module.commands == NULL) {
        module.commands = command;
        return;
    }

    // append to end of list
    command_t* cur = module.commands;
    while(cur->next != NULL) {
        cur = cur->next;
    }
    cur->next = command;
}

void help(int argc, char* argv[]) {
    command_t* command = module.commands;
    while (command != NULL) {
        printf("%s %s\t(%s)\n", command->name, command->usage, command->description);
        command = command->next;
    }
}

void load_module() {
    char* error;
    void* handle = dlopen(LIB, RTLD_LAZY);
    if (!handle) {
        logf("Error on dlopen %s: %s\n", LIB, dlerror());
        exit(EXIT_FAILURE);
    }
    dlerror();
    struct link_map* lm = (struct link_map*) handle;
    module.base = lm->l_addr;

    initialize_module = dlsym(handle, "initialize_module");
    if ((error = dlerror()) != NULL)  {
        logf("%s\n", error);
        exit(1);
    }
    initialize_module(&module, register_command);

    register_command("help", "\t\t\t", "Show this information", help);
    register_command("modinfo", "\t\t", "Show information about the loaded module", module_info);
    /* logf("Module successfully loaded.\n"); */
}

void handle_input(char* buf) {
    int argc = 0;
    char* argv[MAX_ARGC];
    char* token = strtok(buf, " \n");
    if (!token) {
        return;
    }
    while (argc < MAX_ARGC && token) {
        argv[argc] = token;
        argc++;
        token = strtok(NULL, " \n");
    }

    command_t* cur = module.commands;
    while (cur != NULL) {
        if (!strcmp(cur->name, argv[0])) {
            cur->function(argc, argv);
            break;
        }
        cur = cur->next;
    }
    if (cur == NULL) {
        printf("Command not found.\n");
    }
    return;
}

void interact() {
    printf("*\n* %s\n*\n%s\n> ", module.name, module.info);
    fflush(stdout);
    static char buf[4096];
    while (1) {
        if (fgets(buf, 4096, stdin) != NULL) {
            handle_input(buf);
            printf("> ");
        } else {
            break;
        }
    }
}

int main(int argc, char* argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    load_module();
    interact();
}
