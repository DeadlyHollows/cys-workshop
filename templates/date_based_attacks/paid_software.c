#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char** argv) {

    char install_time[21];
    char flag[100];
    long install_at;
    time_t now;

    printf("Checking trial period expiry...");

    for (int i = 0; i < 5; i++) {
        printf(".");
        setvbuf(stdout, NULL, _IONBF, 0);
        // fflush(stdout);
        sleep(1);
    }

    puts("\n");

    int fd = open("/home/my573ry/.sfw/installed_at", O_RDONLY);

    if (read(fd, install_time, 20) > 0) {

        install_at = atol(install_time);

        if (install_at == 0) {
            // Error...
            exit(-1);
        }

        now = time(NULL);

        // 30-day trial period...
        if (now > install_at && (now - install_at) <= (30 * 24 * 60 * 60)) {
            puts("Software at your service :)");
            sleep(3);
            puts("\nBtw in case you need a flag, you earned it as well ;)");

            fd = open("./flag.txt", O_RDONLY);

            if (read(fd, flag, 100) > 0) {
                printf("\n[*] Flag: %s\n", flag);
                return 0;
            }

            else {
                puts("Things don't look right... Maybe try again later? Also make sure to bring the flag file then xP");
                sleep(3);
                puts("Exiting...");
                exit(-1);
            }

        }

    }

    else {
        puts("Things seem to be corrupted! We won't allow that...");
        sleep(3);
        puts("Exiting...");
        exit(-1);
    }

    exit(-1);

}