#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>


int main(int argc, char** argv)
{
    DIR *d;
    struct dirent *dir;
    FILE * fp;
    char * pos;
    char str[0x200];

    if (argc != 3)
    {
        printf("%s folder-ext name-tag\n\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *ext = argv[1];
    const char *tag = argv[2];

    d = opendir(ext);
    if (!d)
        exit(EXIT_FAILURE);

    while ((dir = readdir(d)) != NULL)
    {
        if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0 || strstr(dir->d_name, ext) == NULL)
            continue;

        snprintf(str, sizeof(str), "%s/%s", ext, dir->d_name);

        fp = fopen(str, "r");
        if (fp == NULL)
            exit(EXIT_FAILURE);

        memset(str, 0, sizeof(str));
        fread(str, 1, sizeof(str)-1, fp);
        fclose(fp);

        pos = strstr(str, tag);
        if (pos)
        {
            pos = strchr(pos + strlen(tag), '"');
            *strchr(++pos, '"') = 0;
        }

        printf("%s=%s\n", dir->d_name, pos);
    }

    closedir(d);
    exit(EXIT_SUCCESS);
}
